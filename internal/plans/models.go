package plans

import (
	"time"

	"github.com/google/uuid"
)

type Plan struct {
	ID                    uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID                *uuid.UUID `gorm:"type:uuid;index" json:"user_id,omitempty"`
	Name                  string     `json:"name"`
	Price                 int        `json:"price"`
	DurationMinutes       int        `json:"duration_minutes"`
	DataLimitMB           *int       `json:"data_limit_mb"`
	UploadSpeed           string     `json:"upload_speed"`
	DownloadSpeed         string     `json:"download_speed"`
	MaxDevices            int        `json:"max_devices"`
	IsActive              bool       `gorm:"default:true" json:"is_active"`
	OnlineVouchersCreated int        `gorm:"-" json:"online_vouchers_created,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}
