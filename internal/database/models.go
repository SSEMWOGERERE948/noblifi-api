package database

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Name            string     `json:"name"`
	Email           string     `gorm:"uniqueIndex" json:"email"`
	PasswordHash    string     `json:"-"`
	Role            string     `json:"role"`
	HotspotName     string     `json:"hotspot_name"`
	BillingPlan     string     `json:"billing_plan"`
	MonthlyPriceUGX int        `json:"monthly_price_ugx"`
	TrialEndsAt     *time.Time `json:"trial_ends_at"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (u User) GetID() uuid.UUID {
	return u.ID
}

func (u User) GetRole() string {
	return u.Role
}

func (u User) TrialExpired() bool {
	return u.TrialEndsAt != nil && time.Now().After(*u.TrialEndsAt)
}

type AuthCode struct {
	ID        uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Email     string     `gorm:"index" json:"email"`
	Purpose   string     `gorm:"index" json:"purpose"`
	CodeHash  string     `json:"-"`
	Payload   string     `gorm:"type:text" json:"payload,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at"`
}

type Site struct {
	ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Name      string    `json:"name"`
	Location  *string   `json:"location"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Session struct {
	ID            uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	VoucherID     *uuid.UUID `gorm:"type:uuid" json:"voucher_id"`
	RouterID      *uuid.UUID `gorm:"type:uuid" json:"router_id"`
	Username      string     `json:"username"`
	MacAddress    *string    `json:"mac_address"`
	IPAddress     *string    `json:"ip_address"`
	StartedAt     *time.Time `json:"started_at"`
	StoppedAt     *time.Time `json:"stopped_at"`
	UploadBytes   int64      `gorm:"default:0" json:"upload_bytes"`
	DownloadBytes int64      `gorm:"default:0" json:"download_bytes"`
	Status        string     `gorm:"default:active" json:"status"`
}
