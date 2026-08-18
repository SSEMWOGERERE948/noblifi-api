package payments

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type PaymentOrder struct {
	ID                uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	MerchantReference string         `gorm:"uniqueIndex;not null" json:"merchant_reference"`
	OrderTrackingID   string         `gorm:"index" json:"order_tracking_id"`
	Provider          string         `gorm:"default:iotec;not null" json:"provider"`
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

// BeforeCreate generates the UUID in Go instead of relying on
// PostgreSQL's gen_random_uuid(), allowing SQLite tests to work.
func (p *PaymentOrder) BeforeCreate(_ *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}

	return nil
}
