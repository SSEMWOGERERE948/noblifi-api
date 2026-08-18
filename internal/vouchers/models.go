package vouchers

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Voucher struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    *uuid.UUID `gorm:"type:uuid;index" json:"user_id,omitempty"`
	Code      string     `gorm:"uniqueIndex" json:"code"`
	PlanID    uuid.UUID  `gorm:"type:uuid;index" json:"plan_id"`
	Channel   string     `gorm:"default:physical;index" json:"channel"`
	BatchID   *string    `gorm:"index" json:"batch_id"`
	Template  *string    `json:"template"`
	Pattern   *string    `json:"pattern"`
	Status    string     `gorm:"default:unused" json:"status"`
	StartsAt  *time.Time `json:"starts_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// BeforeCreate generates the UUID in Go.
//
// This avoids using PostgreSQL-specific:
//
//	default:gen_random_uuid()
//
// and allows the model to work with both PostgreSQL
// and SQLite during tests.
func (v *Voucher) BeforeCreate(_ *gorm.DB) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}

	return nil
}