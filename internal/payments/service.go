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
		"provider":   "iotec",
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
	if strings.TrimSpace(input.Phone) == "" {
		return StartOrderResult{}, errors.New("phone is required for ioTec mobile money collection")
	}

	merchantReference := "NOBLIFI-" + strings.ToUpper(randomHex(8))
	order := PaymentOrder{
		ID:                uuid.New(),
		MerchantReference: merchantReference,
		Provider:          "iotec",
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

	response, err := s.submitIotecCollection(order, plan)
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
		Provider:          "iotec",
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
		return OrderStatusResult{}, errors.New("payment order has no ioTec transaction id yet")
	}

	status, err := s.getIotecCollectionStatus(order.OrderTrackingID)
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

func (s *Service) applyStatus(order PaymentOrder, status iotecStatusResponse) (OrderStatusResult, error) {
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
		Provider:          "iotec",
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

type iotecOrderResponse struct {
	OrderTrackingID string
	RedirectURL     string
	raw             map[string]any
}

type iotecStatusResponse struct {
	RawStatus string
	raw       map[string]any
}

func (s *Service) submitIotecCollection(order PaymentOrder, plan plans.Plan) (iotecOrderResponse, error) {
	token, err := s.iotecToken()
	if err != nil {
		return iotecOrderResponse{}, err
	}

	body := map[string]any{
		"category":   "MobileMoney",
		"currency":   order.Currency,
		"walletId":   s.cfg.IotecWalletID,
		"externalId": order.MerchantReference,
		"payer":      order.Phone,
		"amount":     order.Amount,
		"payerNote":  "NobliFi - " + plan.Name,
		"payeeNote":  "NobliFi voucher " + order.MerchantReference,
	}

	var payload map[string]any
	if err := s.iotecRequest(http.MethodPost, "/api/collections/collect", token, body, &payload); err != nil {
		return iotecOrderResponse{}, err
	}

	trackingID := firstString(payload, "id", "requestId", "transactionId")
	if trackingID == "" {
		return iotecOrderResponse{}, fmt.Errorf("ioTec did not return a transaction id: %v", payload)
	}

	return iotecOrderResponse{
		OrderTrackingID: trackingID,
		RedirectURL:     "",
		raw:             payload,
	}, nil
}

func (s *Service) getIotecCollectionStatus(orderTrackingID string) (iotecStatusResponse, error) {
	token, err := s.iotecToken()
	if err != nil {
		return iotecStatusResponse{}, err
	}

	path := "/api/collections/status/" + url.PathEscape(orderTrackingID)
	var payload map[string]any
	if err := s.iotecRequest(http.MethodGet, path, token, nil, &payload); err != nil {
		return iotecStatusResponse{}, err
	}

	rawStatus := firstString(payload, "status", "statusCode", "statusMessage")
	if rawStatus == "" {
		rawStatus = "UNKNOWN"
	}

	return iotecStatusResponse{
		RawStatus: rawStatus,
		raw:       payload,
	}, nil
}

func (s *Service) iotecToken() (string, error) {
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	form := url.Values{}
	form.Set("client_id", s.cfg.IotecClientID)
	form.Set("client_secret", s.cfg.IotecClientSecret)
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequest(http.MethodPost, s.cfg.IotecTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("ioTec auth failed with %d: %s", resp.StatusCode, string(data))
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("decode ioTec auth response: %w", err)
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return "", errors.New("ioTec auth did not return access_token")
	}
	return payload.AccessToken, nil
}

func (s *Service) iotecRequest(method, path, token string, body any, out any) error {
	endpoint := strings.TrimRight(s.cfg.IotecBaseURL, "/") + path

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
		return fmt.Errorf("ioTec request failed with %d: %s", resp.StatusCode, string(data))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode ioTec response: %w", err)
	}
	return nil
}

func (s *Service) configured() error {
	var missing []string
	if s.cfg.IotecBaseURL == "" {
		missing = append(missing, "IOTEC_BASE_URL")
	}
	if s.cfg.IotecTokenURL == "" {
		missing = append(missing, "IOTEC_TOKEN_URL")
	}
	if s.cfg.IotecClientID == "" {
		missing = append(missing, "IOTEC_CLIENT_ID")
	}
	if s.cfg.IotecClientSecret == "" {
		missing = append(missing, "IOTEC_CLIENT_SECRET")
	}
	if s.cfg.IotecWalletID == "" {
		missing = append(missing, "IOTEC_WALLET_ID")
	}
	if len(missing) > 0 {
		return fmt.Errorf("ioTec is not configured. Missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (s *Service) currency() string {
	if s.cfg.IotecCurrency != "" {
		return s.cfg.IotecCurrency
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
