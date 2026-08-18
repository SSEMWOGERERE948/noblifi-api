package database

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	DefaultSubscriptionPriceUGX = 25000
	SubscriptionPriceSettingKey = "subscription_price_ugx"

	// Account subscription states.
	SubscriptionStatusTrial      = "trial"
	SubscriptionStatusSubscribed = "subscribed"
	SubscriptionStatusExpired    = "expired"
	SubscriptionStatusPastDue    = "past_due"
	SubscriptionStatusCancelled  = "cancelled"

	// Default free-trial period.
	DefaultTrialDuration = 14 * 24 * time.Hour
)

// ============================================================
// UUID HELPERS
// ============================================================

// ensureUUID generates a UUID in Go instead of relying on
// PostgreSQL's gen_random_uuid().
//
// This keeps the models compatible with:
// - PostgreSQL in production
// - SQLite in unit tests
func ensureUUID(id *uuid.UUID) {
	if id != nil && *id == uuid.Nil {
		*id = uuid.New()
	}
}

// ============================================================
// USER
// ============================================================

type User struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	Name         string `json:"name"`
	Email        string `gorm:"uniqueIndex" json:"email"`
	PasswordHash string `json:"-"`

	Role        string `json:"role"`
	HotspotName string `json:"hotspot_name"`

	// Subscription information.
	BillingPlan     string `json:"billing_plan"`
	MonthlyPriceUGX int    `json:"monthly_price_ugx"`

	// SubscriptionStatus represents the user's current billing state.
	//
	// Possible values:
	// trial
	// subscribed
	// expired
	// past_due
	// cancelled
	SubscriptionStatus string `gorm:"default:trial;not null" json:"subscription_status"`

	// TrialEndsAt applies only while the account is on trial.
	TrialEndsAt *time.Time `json:"trial_ends_at"`

	// Paid subscription dates.
	SubscriptionStartsAt *time.Time `json:"subscription_starts_at"`
	SubscriptionEndsAt   *time.Time `json:"subscription_ends_at"`

	EmailVerifiedAt *time.Time `json:"email_verified_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (u *User) BeforeCreate(_ *gorm.DB) error {
	ensureUUID(&u.ID)
	return nil
}

func (u User) GetID() uuid.UUID {
	return u.ID
}

func (u User) GetRole() string {
	return u.Role
}

// IsOnTrial returns true when the user is currently
// using the free trial.
func (u User) IsOnTrial() bool {
	return strings.EqualFold(
		strings.TrimSpace(u.SubscriptionStatus),
		SubscriptionStatusTrial,
	)
}

// TrialExpired returns true when the account is still marked
// as trial but its trial end date has passed.
func (u User) TrialExpired() bool {
	if !u.IsOnTrial() {
		return false
	}

	if u.TrialEndsAt == nil {
		return false
	}

	return time.Now().After(*u.TrialEndsAt)
}

// HasActiveSubscription returns true when the user has paid,
// is marked as subscribed, and the subscription has not expired.
func (u User) HasActiveSubscription() bool {
	if !strings.EqualFold(
		strings.TrimSpace(u.SubscriptionStatus),
		SubscriptionStatusSubscribed,
	) {
		return false
	}

	if u.SubscriptionEndsAt == nil {
		return false
	}

	return time.Now().Before(*u.SubscriptionEndsAt)
}

// SubscriptionExpired returns true when a subscribed user's
// paid subscription period has ended.
func (u User) SubscriptionExpired() bool {
	if !strings.EqualFold(
		strings.TrimSpace(u.SubscriptionStatus),
		SubscriptionStatusSubscribed,
	) {
		return false
	}

	if u.SubscriptionEndsAt == nil {
		return false
	}

	return time.Now().After(*u.SubscriptionEndsAt)
}

// HasAccess returns true if the user is either:
// 1. still within their free trial, or
// 2. has a valid paid subscription.
func (u User) HasAccess() bool {
	if u.IsOnTrial() {
		if u.TrialEndsAt == nil {
			return false
		}

		return time.Now().Before(*u.TrialEndsAt)
	}

	return u.HasActiveSubscription()
}

// ============================================================
// APP SETTINGS
// ============================================================

type AppSetting struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	Key   string `gorm:"uniqueIndex;not null" json:"key"`
	Value string `gorm:"not null" json:"value"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (a *AppSetting) BeforeCreate(_ *gorm.DB) error {
	ensureUUID(&a.ID)
	return nil
}

func (a AppSetting) ValueInt() int {
	value := strings.TrimSpace(a.Value)

	if value == "" {
		return DefaultSubscriptionPriceUGX
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return DefaultSubscriptionPriceUGX
	}

	return parsed
}

// SubscriptionPriceUGX returns the configured NobliFi
// monthly subscription price.
func SubscriptionPriceUGX(db *gorm.DB) int {
	var setting AppSetting

	if err := db.
		Where("key = ?", SubscriptionPriceSettingKey).
		First(&setting).
		Error; err != nil {

		return DefaultSubscriptionPriceUGX
	}

	return setting.ValueInt()
}

// SetSubscriptionPriceUGX changes the platform subscription
// price stored in application settings.
func SetSubscriptionPriceUGX(
	db *gorm.DB,
	value int,
) (int, error) {

	if value <= 0 {
		return DefaultSubscriptionPriceUGX, nil
	}

	var setting AppSetting

	err := db.
		Where("key = ?", SubscriptionPriceSettingKey).
		First(&setting).
		Error

	if err != nil {
		setting = AppSetting{
			Key:   SubscriptionPriceSettingKey,
			Value: strconv.Itoa(value),
		}

		if saveErr := db.Create(&setting).Error; saveErr != nil {
			return DefaultSubscriptionPriceUGX, saveErr
		}

		return value, nil
	}

	setting.Value = strconv.Itoa(value)

	if saveErr := db.Save(&setting).Error; saveErr != nil {
		return DefaultSubscriptionPriceUGX, saveErr
	}

	return value, nil
}

// ============================================================
// AUTH CODE
// ============================================================

type AuthCode struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	Email   string `gorm:"index" json:"email"`
	Purpose string `gorm:"index" json:"purpose"`

	CodeHash string `json:"-"`

	Payload string `gorm:"type:text" json:"payload,omitempty"`

	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`

	CreatedAt time.Time `json:"created_at"`
}

func (a *AuthCode) BeforeCreate(_ *gorm.DB) error {
	ensureUUID(&a.ID)
	return nil
}

// ============================================================
// SITE
// ============================================================

type Site struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	Name     string  `json:"name"`
	Location *string `json:"location"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Site) BeforeCreate(_ *gorm.DB) error {
	ensureUUID(&s.ID)
	return nil
}

// ============================================================
// SESSION
// ============================================================

type Session struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	VoucherID *uuid.UUID `gorm:"type:uuid" json:"voucher_id"`
	RouterID  *uuid.UUID `gorm:"type:uuid" json:"router_id"`

	Username   string  `json:"username"`
	MacAddress *string `json:"mac_address"`
	IPAddress  *string `json:"ip_address"`

	StartedAt *time.Time `json:"started_at"`
	StoppedAt *time.Time `json:"stopped_at"`

	UploadBytes   int64 `gorm:"default:0" json:"upload_bytes"`
	DownloadBytes int64 `gorm:"default:0" json:"download_bytes"`

	Status string `gorm:"default:active" json:"status"`
}

func (s *Session) BeforeCreate(_ *gorm.DB) error {
	ensureUUID(&s.ID)
	return nil
}
