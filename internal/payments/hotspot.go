package payments

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// HotspotPurchase is deliberately isolated from PaymentOrder because
// PaymentOrder also drives NobliFi account/subscription activation.
type HotspotPurchase struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	OwnerUserID uuid.UUID `gorm:"type:uuid;index;not null" json:"owner_user_id"`
	RouterID    uuid.UUID `gorm:"type:uuid;index;not null" json:"router_id"`
	PlanID      uuid.UUID `gorm:"type:uuid;index;not null" json:"plan_id"`
	DeviceMAC   string    `gorm:"size:17;index;not null" json:"device_mac"`

	MerchantReference  string `gorm:"uniqueIndex;not null" json:"merchant_reference"`
	LocalTransactionID string `gorm:"size:9;uniqueIndex" json:"transaction_id"`
	OrderTrackingID    string `gorm:"index" json:"order_tracking_id"`
	Provider           string `gorm:"default:iotec" json:"provider"`
	Status             string `gorm:"default:pending;index" json:"status"`
	RawStatus          string `json:"raw_status"`
	Amount             int    `json:"amount"`
	Currency           string `json:"currency"`
	CustomerName       string `gorm:"size:160;index" json:"customer_name"`
	Phone              string `gorm:"size:32;index" json:"phone"`
	Email              string `json:"email"`

	VoucherID       *uuid.UUID     `gorm:"type:uuid;index" json:"voucher_id,omitempty"`
	ProviderPayload datatypes.JSON `gorm:"type:json" json:"-"`
	PaidAt          *time.Time     `gorm:"index" json:"paid_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func (p *HotspotPurchase) BeforeCreate(_ *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

type HotspotOrderInput struct {
	OwnerUserID  uuid.UUID
	RouterID     uuid.UUID
	PlanID       uuid.UUID
	DeviceMAC    string
	Phone        string
	Email        string
	CustomerName string
}

type HotspotOrderResult struct {
	Provider          string `json:"provider"`
	MerchantReference string `json:"merchant_reference"`
	TransactionID     string `json:"transaction_id"`
	OrderTrackingID   string `json:"order_tracking_id"`
	RedirectURL       string `json:"redirect_url"`
	Status            string `json:"status"`
}

type HotspotOrderStatusInput struct {
	OwnerUserID uuid.UUID
	RouterID    uuid.UUID
	PaymentID   string
	DeviceMAC   string
}

type HotspotOrderStatusResult struct {
	Success           bool   `json:"success"`
	Provider          string `json:"provider"`
	Status            string `json:"status"`
	RawStatus         string `json:"raw_status"`
	MerchantReference string `json:"merchant_reference"`
	TransactionID     string `json:"transaction_id"`
	OrderTrackingID   string `json:"order_tracking_id"`
	Voucher           string `json:"voucher,omitempty"`
	AutoConnect       bool   `json:"auto_connect"`
}

func (s *Service) EnsureHotspotPurchaseSchema() error {
	return s.db.AutoMigrate(&HotspotPurchase{})
}

func (s *Service) StartHotspotOrder(input HotspotOrderInput) (HotspotOrderResult, error) {
	if err := s.configured(); err != nil {
		return HotspotOrderResult{}, err
	}
	if input.OwnerUserID == uuid.Nil || input.RouterID == uuid.Nil || input.PlanID == uuid.Nil {
		return HotspotOrderResult{}, errors.New("invalid hotspot purchase scope")
	}

	mac, err := normalizeHotspotPurchaseMAC(input.DeviceMAC)
	if err != nil {
		return HotspotOrderResult{}, err
	}
	customerName := strings.TrimSpace(input.CustomerName)
	phone, err := normalizeUgandaPhone(input.Phone)
	if err != nil {
		return HotspotOrderResult{}, err
	}
	if customerName == "" {
		customerName = phone
	}

	var router routers.Router
	if err := s.db.Where("id = ? AND user_id = ?", input.RouterID, input.OwnerUserID).First(&router).Error; err != nil {
		return HotspotOrderResult{}, errors.New("hotspot router not found")
	}

	var plan plans.Plan
	if err := s.db.Where("id = ? AND user_id = ? AND is_active = ?", input.PlanID, input.OwnerUserID, true).First(&plan).Error; err != nil {
		return HotspotOrderResult{}, errors.New("package not found")
	}
	if plan.Price <= 0 {
		return HotspotOrderResult{}, errors.New("package price must be greater than zero")
	}

	merchantReference := "NOBLIFI-HS-" + strings.ToUpper(randomHex(8))
	transactionID, err := s.generateLocalTransactionID()
	if err != nil {
		return HotspotOrderResult{}, err
	}
	purchase := HotspotPurchase{
		ID: uuid.New(), OwnerUserID: input.OwnerUserID, RouterID: input.RouterID,
		PlanID: input.PlanID, DeviceMAC: mac, MerchantReference: merchantReference, LocalTransactionID: transactionID,
		Provider: "iotec", Status: "pending", Amount: plan.Price, Currency: s.currency(),
		CustomerName: customerName, Phone: phone, Email: strings.TrimSpace(input.Email),
	}
	if err := s.db.Create(&purchase).Error; err != nil {
		return HotspotOrderResult{}, err
	}

	// Ephemeral provider object only: it is intentionally NOT saved to
	// payment_orders, which is the NobliFi subscription payment flow.
	providerOrder := PaymentOrder{
		ID: purchase.ID, MerchantReference: purchase.MerchantReference,
		Provider: purchase.Provider, Status: purchase.Status, PlanID: purchase.PlanID,
		Amount: purchase.Amount, Currency: purchase.Currency, Phone: purchase.Phone, Email: purchase.Email,
	}
	response, err := s.submitIotecCollection(providerOrder, plan)
	if err != nil {
		_ = s.db.Model(&HotspotPurchase{}).Where("id = ?", purchase.ID).Update("status", "failed").Error
		return HotspotOrderResult{}, err
	}

	payload, _ := json.Marshal(response.raw)
	if err := s.db.Model(&HotspotPurchase{}).Where("id = ?", purchase.ID).Updates(map[string]any{
		"order_tracking_id": response.OrderTrackingID,
		"provider_payload":  datatypes.JSON(payload),
	}).Error; err != nil {
		return HotspotOrderResult{}, err
	}

	return HotspotOrderResult{
		Provider: "iotec", MerchantReference: merchantReference,
		TransactionID: transactionID, OrderTrackingID: response.OrderTrackingID, RedirectURL: response.RedirectURL, Status: "pending",
	}, nil
}

func (s *Service) CheckHotspotOrder(input HotspotOrderStatusInput) (HotspotOrderStatusResult, error) {
	paymentID := strings.TrimSpace(input.PaymentID)
	if paymentID == "" {
		return HotspotOrderStatusResult{}, errors.New("payment order id is required")
	}
	mac, err := normalizeHotspotPurchaseMAC(input.DeviceMAC)
	if err != nil {
		return HotspotOrderStatusResult{}, err
	}

	var purchase HotspotPurchase
	if err := s.db.Where(
		"owner_user_id = ? AND router_id = ? AND device_mac = ? AND (local_transaction_id = ? OR order_tracking_id = ? OR merchant_reference = ?)",
		input.OwnerUserID, input.RouterID, mac, paymentID, paymentID, paymentID,
	).First(&purchase).Error; err != nil {
		return HotspotOrderStatusResult{}, errors.New("hotspot payment not found")
	}
	if strings.TrimSpace(purchase.OrderTrackingID) == "" {
		return HotspotOrderStatusResult{}, errors.New("hotspot payment has no ioTec transaction id yet")
	}

	status, err := s.getIotecCollectionStatus(purchase.OrderTrackingID)
	if err != nil {
		return HotspotOrderStatusResult{}, err
	}
	normalized := normalizePaymentStatus(status.RawStatus)
	persistedStatus := normalized
	if persistedStatus == "unpaid" {
		persistedStatus = "pending"
	}
	payload, _ := json.Marshal(status.raw)
	updates := map[string]any{
		"status": persistedStatus, "raw_status": status.RawStatus, "provider_payload": datatypes.JSON(payload),
	}
	if payerName := extractIotecCustomerName(status.raw); payerName != "" {
		updates["customer_name"] = payerName
		purchase.CustomerName = payerName
	}
	if normalized == "paid" && purchase.PaidAt == nil {
		now := time.Now()
		updates["paid_at"] = &now
		purchase.PaidAt = &now
	}
	if err := s.db.Model(&HotspotPurchase{}).Where("id = ?", purchase.ID).Updates(updates).Error; err != nil {
		return HotspotOrderStatusResult{}, err
	}

	voucherCode := ""
	if normalized == "paid" {
		if s.hotspotSettlement == nil {
			return HotspotOrderStatusResult{}, errors.New("hotspot settlement service is unavailable")
		}
		settlement, err := s.hotspotSettlement.SettlePaidHotspotPurchase(purchase.ID)
		if err != nil {
			return HotspotOrderStatusResult{}, err
		}
		voucherCode = settlement.VoucherCode
	}

	return HotspotOrderStatusResult{
		Success: normalized == "paid", Provider: "iotec", Status: normalized, RawStatus: status.RawStatus,
		MerchantReference: purchase.MerchantReference, TransactionID: purchase.LocalTransactionID, OrderTrackingID: purchase.OrderTrackingID, Voucher: voucherCode,
		AutoConnect: voucherCode != "",
	}, nil
}

func (s *Service) generateLocalTransactionID() (string, error) {
	const maxAttempts = 50
	for attempt := 0; attempt < maxAttempts; attempt++ {
		code, err := randomNumericCode(9)
		if err != nil {
			return "", err
		}
		var count int64
		if err := s.db.Model(&HotspotPurchase{}).Where("local_transaction_id = ?", code).Count(&count).Error; err != nil {
			return "", err
		}
		if count == 0 {
			if err := s.db.Model(&vouchers.Voucher{}).Where("code = ?", code).Count(&count).Error; err != nil {
				return "", err
			}
		}
		if count == 0 {
			return code, nil
		}
	}
	return "", fmt.Errorf("could not generate unique 9-digit transaction id")
}

func randomNumericCode(length int) (string, error) {
	var builder strings.Builder
	builder.Grow(length)
	max := big.NewInt(10)
	for i := 0; i < length; i++ {
		value, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		builder.WriteByte(byte('0' + value.Int64()))
	}
	return builder.String(), nil
}

func normalizeHotspotPurchaseMAC(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return "", errors.New("device MAC is required")
	}
	var raw strings.Builder
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			raw.WriteRune(r)
		case r == ':' || r == '-' || r == '.' || r == ' ':
			continue
		default:
			return "", errors.New("invalid device MAC")
		}
	}
	hex := raw.String()
	if len(hex) != 12 {
		return "", errors.New("invalid device MAC")
	}
	parts := make([]string, 0, 6)
	for i := 0; i < 12; i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":"), nil
}

func normalizeUgandaPhone(value string) (string, error) {
	var digits strings.Builder
	for _, r := range strings.TrimSpace(value) {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	phone := digits.String()
	switch {
	case strings.HasPrefix(phone, "0") && len(phone) == 10:
		phone = "256" + phone[1:]
	case strings.HasPrefix(phone, "7") && len(phone) == 9:
		phone = "256" + phone
	case strings.HasPrefix(phone, "256") && len(phone) == 12:
	default:
		return "", errors.New("phone must be a valid Uganda mobile money number")
	}
	if len(phone) != 12 || !strings.HasPrefix(phone, "2567") {
		return "", errors.New("phone must be a valid Uganda mobile money number")
	}
	return phone, nil
}

func extractIotecCustomerName(payload map[string]any) string {
	for _, key := range []string{
		"customerName",
		"customer_name",
		"payerName",
		"payer_name",
		"accountName",
		"account_name",
		"name",
	} {
		if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}

	for _, key := range []string{"customer", "payer", "account", "data"} {
		nested, ok := payload[key].(map[string]any)
		if !ok {
			continue
		}
		if value := extractIotecCustomerName(nested); value != "" {
			return value
		}
	}

	return ""
}
