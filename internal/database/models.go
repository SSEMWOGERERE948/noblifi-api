package database

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                   uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Name                 string     `json:"name"`
	Email                string     `gorm:"uniqueIndex" json:"email"`
	PortalName           string     `json:"portal_name"`
	PasswordHash         string     `json:"-"`
	Role                 string     `gorm:"default:client;index" json:"role"`
	AccountStatus        string     `gorm:"default:pending;index" json:"account_status"`
	RouterLimit          int        `gorm:"default:3" json:"router_limit"`
	RouterLimitRequested *int       `json:"router_limit_requested"`
	ApprovedAt           *time.Time `json:"approved_at"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

type ConfirmationCode struct {
	ID        uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"user_id"`
	Email     string     `gorm:"index;not null" json:"email"`
	Action    string     `gorm:"index;not null" json:"action"`
	CodeHash  string     `gorm:"not null" json:"-"`
	ExpiresAt time.Time  `gorm:"index;not null" json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at"`
}

type RouterLimitRequest struct {
	ID             uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID         uuid.UUID  `gorm:"type:uuid;index;not null" json:"user_id"`
	RequestedLimit int        `json:"requested_limit"`
	Status         string     `gorm:"default:pending;index" json:"status"`
	Reason         string     `json:"reason"`
	DecidedByID    *uuid.UUID `gorm:"type:uuid;index" json:"decided_by_id"`
	DecidedAt      *time.Time `json:"decided_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
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
