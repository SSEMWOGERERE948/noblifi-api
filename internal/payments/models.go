package payments

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type PaymentOrder struct {
	ID                uuid.UUID      `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	MerchantReference string         `gorm:"uniqueIndex;not null" json:"merchant_reference"`
	OrderTrackingID   string         `gorm:"index" json:"order_tracking_id"`
	Provider          string         `gorm:"default:pesapal;not null" json:"provider"`
	Status            string         `gorm:"default:pending;index;not null" json:"status"`
	RawStatus         string         `json:"raw_status"`
	PlanID            uuid.UUID      `gorm:"type:uuid;index;not null" json:"plan_id"`
	Amount            int            `json:"amount"`
	Currency          string         `gorm:"default:UGX;not null" json:"currency"`
	Phone             string         `json:"phone"`
	Email             string         `json:"email"`
	VoucherID         *uuid.UUID     `gorm:"type:uuid;index" json:"voucher_id"`
	ProviderPayload   datatypes.JSON `json:"provider_payload"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}
