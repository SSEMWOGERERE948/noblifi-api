package payments

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// HotspotPurchase is deliberately isolated from PaymentOrder because
// PaymentOrder also drives NobliFi account/subscription activation.
type HotspotPurchase struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	OwnerUserID uuid.UUID `gorm:"type:uuid;index;not null" json:"owner_user_id"`
	RouterID    uuid.UUID `gorm:"type:uuid;index;not null" json:"router_id"`
	PlanID      uuid.UUID `gorm:"type:uuid;index;not null" json:"plan_id"`
	DeviceMAC   string    `gorm:"size:17;index;not null" json:"device_mac"`

	MerchantReference string `gorm:"uniqueIndex;not null" json:"merchant_reference"`
	OrderTrackingID   string `gorm:"index" json:"order_tracking_id"`
	Provider          string `gorm:"default:iotec" json:"provider"`
	Status            string `gorm:"default:pending;index" json:"status"`
	RawStatus         string `json:"raw_status"`
	Amount            int    `json:"amount"`
	Currency          string `json:"currency"`
	Phone             string `json:"phone"`
	Email             string `json:"email"`

	VoucherID       *uuid.UUID     `gorm:"type:uuid;index" json:"voucher_id,omitempty"`
	ProviderPayload datatypes.JSON `gorm:"type:json" json:"-"`
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
	OwnerUserID uuid.UUID
	RouterID    uuid.UUID
	PlanID      uuid.UUID
	DeviceMAC   string
	Phone       string
	Email       string
}

type HotspotOrderResult struct {
	Provider          string `json:"provider"`
	MerchantReference string `json:"merchant_reference"`
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
	OrderTrackingID   string `json:"order_tracking_id"`
	Voucher           string `json:"voucher,omitempty"`
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
	phone := strings.TrimSpace(input.Phone)
	if phone == "" {
		return HotspotOrderResult{}, errors.New("phone is required for ioTec mobile money collection")
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
	purchase := HotspotPurchase{
		ID: uuid.New(), OwnerUserID: input.OwnerUserID, RouterID: input.RouterID,
		PlanID: input.PlanID, DeviceMAC: mac, MerchantReference: merchantReference,
		Provider: "iotec", Status: "pending", Amount: plan.Price, Currency: s.currency(),
		Phone: phone, Email: strings.TrimSpace(input.Email),
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
		OrderTrackingID: response.OrderTrackingID, RedirectURL: response.RedirectURL, Status: "pending",
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
		"owner_user_id = ? AND router_id = ? AND device_mac = ? AND (order_tracking_id = ? OR merchant_reference = ?)",
		input.OwnerUserID, input.RouterID, mac, paymentID, paymentID,
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
	if err := s.db.Model(&HotspotPurchase{}).Where("id = ?", purchase.ID).Updates(map[string]any{
		"status": persistedStatus, "raw_status": status.RawStatus, "provider_payload": datatypes.JSON(payload),
	}).Error; err != nil {
		return HotspotOrderStatusResult{}, err
	}

	voucherCode := ""
	if normalized == "paid" {
		voucher, err := s.ensureHotspotVoucher(purchase)
		if err != nil {
			return HotspotOrderStatusResult{}, err
		}
		voucherCode = voucher.Code
		if s.radius != nil {
			if err := s.radius.SyncVoucherForVoucher(voucher.Code); err != nil {
				return HotspotOrderStatusResult{}, fmt.Errorf("hotspot voucher created but RADIUS sync failed: %w", err)
			}
		}
	}

	return HotspotOrderStatusResult{
		Success: normalized == "paid", Provider: "iotec", Status: normalized, RawStatus: status.RawStatus,
		MerchantReference: purchase.MerchantReference, OrderTrackingID: purchase.OrderTrackingID, Voucher: voucherCode,
	}, nil
}

func (s *Service) ensureHotspotVoucher(purchase HotspotPurchase) (vouchers.Voucher, error) {
	var result vouchers.Voucher
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var locked HotspotPurchase
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&locked, "id = ?", purchase.ID).Error; err != nil {
			return err
		}
		if locked.VoucherID != nil {
			if err := tx.First(&result, "id = ?", *locked.VoucherID).Error; err == nil {
				return nil
			}
		}
		for attempt := 0; attempt < 8; attempt++ {
			ownerID := locked.OwnerUserID
			result = vouchers.Voucher{
				ID: uuid.New(), UserID: &ownerID, Code: "NF-" + strings.ToUpper(randomHex(4)),
				PlanID: locked.PlanID, Channel: "online", Status: "unused",
			}
			if err := tx.Create(&result).Error; err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
					continue
				}
				return err
			}
			locked.VoucherID = &result.ID
			locked.Status = "paid"
			return tx.Save(&locked).Error
		}
		return errors.New("could not generate unique hotspot voucher code")
	})
	return result, err
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