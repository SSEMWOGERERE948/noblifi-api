package payments

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type RadiusVoucherSyncer interface {
	SyncVoucherForVoucher(code string) error
}

type Service struct {
	db     *gorm.DB
	cfg    config.Config
	radius RadiusVoucherSyncer
	client *http.Client
}

type StartOrderInput struct {
	PlanID string `json:"plan_id"`
	Phone  string `json:"phone"`
	Email  string `json:"email"`
}

type StartOrderResult struct {
	Provider          string `json:"provider"`
	MerchantReference string `json:"merchant_reference"`
	OrderTrackingID   string `json:"order_tracking_id"`
	RedirectURL       string `json:"redirect_url"`
}

type OrderStatusResult struct {
	Success           bool            `json:"success"`
	Provider          string          `json:"provider"`
	Status            string          `json:"status"`
	RawStatus         string          `json:"raw_status"`
	MerchantReference string          `json:"merchant_reference"`
	OrderTrackingID   string          `json:"order_tracking_id"`
	Voucher           string          `json:"voucher"`
	Payload           json.RawMessage `json:"payload,omitempty"`
}

func NewService(db *gorm.DB, cfg config.Config, radius RadiusVoucherSyncer) *Service {
	return &Service{
		db:     db,
		cfg:    cfg,
		radius: radius,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *Service) PublicConfig() map[string]any {
	return map[string]any{
		"provider":   "pesapal",
		"configured": s.configured() == nil,
		"currency":   s.currency(),
	}
}

func (s *Service) StartOrder(input StartOrderInput) (StartOrderResult, error) {
	if err := s.configured(); err != nil {
		return StartOrderResult{}, err
	}

	planID, err := uuid.Parse(strings.TrimSpace(input.PlanID))
	if err != nil {
		return StartOrderResult{}, errors.New("invalid plan_id")
	}

	var plan plans.Plan
	if err := s.db.First(&plan, "id = ? AND is_active = ?", planID, true).Error; err != nil {
		return StartOrderResult{}, errors.New("package not found")
	}
	if plan.Price <= 0 {
		return StartOrderResult{}, errors.New("package price must be greater than zero")
	}

	merchantReference := "NOBLIFI-" + strings.ToUpper(randomHex(8))
	order := PaymentOrder{
		ID:                uuid.New(),
		MerchantReference: merchantReference,
		Provider:          "pesapal",
		Status:            "pending",
		PlanID:            plan.ID,
		Amount:            plan.Price,
		Currency:          s.currency(),
		Phone:             strings.TrimSpace(input.Phone),
		Email:             strings.TrimSpace(input.Email),
	}
	if err := s.db.Create(&order).Error; err != nil {
		return StartOrderResult{}, err
	}

	response, err := s.submitPesapalOrder(order, plan)
	if err != nil {
		return StartOrderResult{}, err
	}

	payload, _ := json.Marshal(response.raw)
	if err := s.db.Model(&PaymentOrder{}).
		Where("merchant_reference = ?", merchantReference).
		Updates(map[string]any{
			"order_tracking_id": response.OrderTrackingID,
			"provider_payload":  datatypes.JSON(payload),
		}).Error; err != nil {
		return StartOrderResult{}, err
	}

	return StartOrderResult{
		Provider:          "pesapal",
		MerchantReference: merchantReference,
		OrderTrackingID:   response.OrderTrackingID,
		RedirectURL:       response.RedirectURL,
	}, nil
}

func (s *Service) CheckOrder(id string) (OrderStatusResult, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return OrderStatusResult{}, errors.New("payment order id is required")
	}

	var order PaymentOrder
	err := s.db.
		Where("order_tracking_id = ? OR merchant_reference = ?", id, id).
		First(&order).
		Error
	if err != nil {
		return OrderStatusResult{}, errors.New("payment order not found")
	}
	if order.OrderTrackingID == "" {
		return OrderStatusResult{}, errors.New("payment order has no Pesapal tracking id yet")
	}

	status, err := s.getPesapalTransactionStatus(order.OrderTrackingID)
	if err != nil {
		return OrderStatusResult{}, err
	}

	return s.applyStatus(order, status)
}

func (s *Service) HandleIPN(orderTrackingID, merchantReference string) (OrderStatusResult, error) {
	id := strings.TrimSpace(orderTrackingID)
	if id == "" {
		id = strings.TrimSpace(merchantReference)
	}
	return s.CheckOrder(id)
}

func (s *Service) applyStatus(order PaymentOrder, status pesapalStatusResponse) (OrderStatusResult, error) {
	normalized := normalizePaymentStatus(status.RawStatus)
	updateStatus := normalized
	if updateStatus == "unpaid" {
		updateStatus = "pending"
	}

	payload, _ := json.Marshal(status.raw)
	order.Status = updateStatus
	order.RawStatus = status.RawStatus
	order.ProviderPayload = datatypes.JSON(payload)

	var voucherCode string
	if normalized == "paid" {
		voucher, err := s.ensureVoucher(&order)
		if err != nil {
			return OrderStatusResult{}, err
		}
		voucherCode = voucher.Code
	}

	if err := s.db.Save(&order).Error; err != nil {
		return OrderStatusResult{}, err
	}

	return OrderStatusResult{
		Success:           normalized == "paid",
		Provider:          "pesapal",
		Status:            normalized,
		RawStatus:         status.RawStatus,
		MerchantReference: order.MerchantReference,
		OrderTrackingID:   order.OrderTrackingID,
		Voucher:           voucherCode,
		Payload:           json.RawMessage(payload),
	}, nil
}

func (s *Service) ensureVoucher(order *PaymentOrder) (vouchers.Voucher, error) {
	if order.VoucherID != nil {
		var existing vouchers.Voucher
		if err := s.db.First(&existing, "id = ?", *order.VoucherID).Error; err == nil {
			return existing, nil
		}
	}

	var voucher vouchers.Voucher
	err := s.db.Transaction(func(tx *gorm.DB) error {
		for attempt := 0; attempt < 5; attempt++ {
			voucher = vouchers.Voucher{
				ID:     uuid.New(),
				Code:   "NF-" + strings.ToUpper(randomHex(4)),
				PlanID: order.PlanID,
				Status: "unused",
			}
			if err := tx.Create(&voucher).Error; err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
					continue
				}
				return err
			}
			order.VoucherID = &voucher.ID
			return nil
		}
		return errors.New("could not generate unique voucher code")
	})
	if err != nil {
		return voucher, err
	}

	if s.radius != nil {
		if err := s.radius.SyncVoucherForVoucher(voucher.Code); err != nil {
			return voucher, fmt.Errorf("voucher created but RADIUS sync failed: %w", err)
		}
	}

	return voucher, nil
}

type pesapalOrderResponse struct {
	OrderTrackingID string
	RedirectURL     string
	raw             map[string]any
}

type pesapalStatusResponse struct {
	RawStatus string
	raw       map[string]any
}

func (s *Service) submitPesapalOrder(order PaymentOrder, plan plans.Plan) (pesapalOrderResponse, error) {
	token, err := s.pesapalToken()
	if err != nil {
		return pesapalOrderResponse{}, err
	}

	callbackURL := strings.TrimRight(s.cfg.FrontendURL, "/") + "/buy"
	body := map[string]any{
		"id":              order.MerchantReference,
		"currency":        order.Currency,
		"amount":          order.Amount,
		"description":     "NobliFi - " + plan.Name,
		"callback_url":    callbackURL,
		"notification_id": s.cfg.PesapalIPNID,
		"billing_address": map[string]any{
			"email_address": emptyToNil(order.Email),
			"phone_number":  emptyToNil(order.Phone),
			"country_code":  "UG",
		},
	}

	var payload map[string]any
	if err := s.pesapalRequest(http.MethodPost, "/Transactions/SubmitOrderRequest", token, body, &payload); err != nil {
		return pesapalOrderResponse{}, err
	}

	trackingID, _ := payload["order_tracking_id"].(string)
	redirectURL, _ := payload["redirect_url"].(string)
	if trackingID == "" || redirectURL == "" {
		return pesapalOrderResponse{}, fmt.Errorf("Pesapal did not return redirect_url/order_tracking_id: %v", payload)
	}

	return pesapalOrderResponse{
		OrderTrackingID: trackingID,
		RedirectURL:     redirectURL,
		raw:             payload,
	}, nil
}

func (s *Service) getPesapalTransactionStatus(orderTrackingID string) (pesapalStatusResponse, error) {
	token, err := s.pesapalToken()
	if err != nil {
		return pesapalStatusResponse{}, err
	}

	path := "/Transactions/GetTransactionStatus?orderTrackingId=" + url.QueryEscape(orderTrackingID)
	var payload map[string]any
	if err := s.pesapalRequest(http.MethodGet, path, token, nil, &payload); err != nil {
		return pesapalStatusResponse{}, err
	}

	rawStatus := firstString(payload, "payment_status_description", "status", "payment_status")
	if rawStatus == "" {
		rawStatus = "UNKNOWN"
	}

	return pesapalStatusResponse{
		RawStatus: rawStatus,
		raw:       payload,
	}, nil
}

func (s *Service) pesapalToken() (string, error) {
	var payload struct {
		Token string `json:"token"`
	}
	body := map[string]string{
		"consumer_key":    s.cfg.PesapalConsumerKey,
		"consumer_secret": s.cfg.PesapalConsumerSecret,
	}
	if err := s.pesapalRequest(http.MethodPost, "/Auth/RequestToken", "", body, &payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Token) == "" {
		return "", errors.New("Pesapal auth did not return token")
	}
	return payload.Token, nil
}

func (s *Service) pesapalRequest(method, path, token string, body any, out any) error {
	endpoint := strings.TrimRight(s.cfg.PesapalBaseURL, "/") + path

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Pesapal request failed with %d: %s", resp.StatusCode, string(data))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode Pesapal response: %w", err)
	}
	return nil
}

func (s *Service) configured() error {
	var missing []string
	if s.cfg.PesapalBaseURL == "" {
		missing = append(missing, "PESAPAL_BASE_URL")
	}
	if s.cfg.PesapalConsumerKey == "" {
		missing = append(missing, "PESAPAL_CONSUMER_KEY")
	}
	if s.cfg.PesapalConsumerSecret == "" {
		missing = append(missing, "PESAPAL_CONSUMER_SECRET")
	}
	if s.cfg.PesapalIPNID == "" {
		missing = append(missing, "PESAPAL_IPN_ID")
	}
	if s.cfg.FrontendURL == "" {
		missing = append(missing, "FRONTEND_URL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("Pesapal is not configured. Missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (s *Service) currency() string {
	if s.cfg.PesapalCurrency != "" {
		return s.cfg.PesapalCurrency
	}
	return "UGX"
}

func normalizePaymentStatus(raw string) string {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(status, "completed"),
		strings.Contains(status, "paid"),
		strings.Contains(status, "success"):
		return "paid"
	case strings.Contains(status, "failed"),
		strings.Contains(status, "invalid"),
		strings.Contains(status, "cancelled"),
		strings.Contains(status, "canceled"),
		strings.Contains(status, "reversed"):
		return "failed"
	default:
		return "unpaid"
	}
}

func randomHex(byteCount int) string {
	bytes := make([]byte, byteCount)
	if _, err := rand.Read(bytes); err != nil {
		return strings.ReplaceAll(uuid.NewString()[:byteCount*2], "-", "")
	}
	return hex.EncodeToString(bytes)
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func emptyToNil(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}
