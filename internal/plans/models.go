package plans

import (
	"time"

	"github.com/google/uuid"
)

const (
	DurationUnitMinutes = "minutes"
	DurationUnitHours   = "hours"
	DurationUnitWeeks   = "weeks"
	DurationUnitMonths  = "months"
)

type Plan struct {
	ID     uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID *uuid.UUID `gorm:"type:uuid;index" json:"user_id,omitempty"`

	Name  string `json:"name"`
	Price int    `json:"price"`

	DurationValue   int    `gorm:"not null;default:1" json:"duration_value"`
	DurationUnit    string `gorm:"size:16;not null;default:minutes" json:"duration_unit"`
	DurationMinutes int    `gorm:"not null" json:"duration_minutes"`

	DataLimitMB *int `json:"data_limit_mb"`

	UploadSpeed   string `json:"upload_speed"`
	DownloadSpeed string `json:"download_speed"`

	MaxDevices int  `gorm:"not null;default:1" json:"max_devices"`
	IsActive   bool `gorm:"not null;default:true" json:"is_active"`

	OnlineVouchersCreated int `gorm:"-" json:"online_vouchers_created,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PatchInput struct {
	Name *string `json:"name"`

	Price *int `json:"price"`

	DurationValue   *int    `json:"duration_value"`
	DurationUnit    *string `json:"duration_unit"`
	DurationMinutes *int    `json:"duration_minutes"`

	DataLimitMB *int `json:"data_limit_mb"`

	UploadSpeed   *string `json:"upload_speed"`
	DownloadSpeed *string `json:"download_speed"`

	MaxDevices *int  `json:"max_devices"`
	IsActive   *bool `json:"is_active"`
}