package radius

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/placeholders"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrVoucherUnavailable          = errors.New("voucher is not available")
	ErrVoucherExpired              = errors.New("voucher has expired")
	ErrVoucherDataExhausted        = errors.New("voucher data allowance is exhausted")
	ErrVoucherBoundToAnotherDevice = errors.New("voucher is already bound to another device")
	ErrInvalidDeviceMAC            = errors.New("invalid device MAC address")
)

type Service struct {
	db *gorm.DB
}

type VoucherRadiusState struct {
	Username       string `json:"username"`
	Status         string `json:"status"`
	SessionTimeout int    `json:"session_timeout"`
	RateLimit      string `json:"rate_limit"`
	MaxDevices     int    `json:"max_devices"`
	DeviceMAC      string `json:"device_mac,omitempty"`
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

func (s *Service) RegisterNAS(nasName, shortName, secret, description string) error {
	nasName = strings.TrimSpace(nasName)
	if nasName == "" {
		return nil
	}

	shortName = strings.TrimSpace(shortName)
	if shortName == "" {
		shortName = nasName
	}

	secret = strings.TrimSpace(secret)
	if placeholders.Is(secret) {
		secret = "noblifi"
	}

	var nas NAS
	err := s.db.First(&nas, "nasname = ?", nasName).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		nas = NAS{
			NASName:     nasName,
			ShortName:   shortName,
			Type:        "mikrotik",
			Secret:      secret,
			Description: description,
		}
		return s.db.Create(&nas).Error
	}
	if err != nil {
		return err
	}

	nas.ShortName = shortName
	nas.Type = "mikrotik"
	nas.Secret = secret
	nas.Description = description

	return s.db.Save(&nas).Error
}

// AuthorizeVoucher performs the generic voucher validity check.
//
// "used" is accepted as a LEGACY ACTIVE status because older accounting
// hooks changed unused -> used. Treating "used" as invalid caused a voucher
// to work once and then fail after logout even while its validity remained.
//
// New code should use "active" for an already-started voucher.
func (s *Service) AuthorizeVoucher(code string) (bool, error) {
	code = normalizeVoucherCode(code)
	if code == "" {
		return false, nil
	}

	var voucher vouchers.Voucher
	if err := s.db.First(&voucher, "code = ?", code).Error; err != nil {
		return false, err
	}

	now := time.Now().UTC()

	if !voucherStatusAllowsLogin(voucher.Status) {
		return false, nil
	}

	if voucherExpired(voucher, now) {
		return false, nil
	}

	var plan plans.Plan
	if err := s.db.First(&plan, "id = ?", voucher.PlanID).Error; err != nil {
		return false, err
	}
	if !plan.IsActive {
		return false, nil
	}

	remainingBytes, limited, err := remainingVoucherDataBytes(s.db, voucher.Code, plan)
	if err != nil {
		return false, err
	}
	if limited && remainingBytes <= 0 {
		_ = s.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&vouchers.Voucher{}).
				Where("id = ?", voucher.ID).
				Update("status", "exhausted").Error; err != nil {
				return err
			}
			return revokeVoucherRadius(tx, voucher.Code)
		})
		return false, nil
	}

	return true, nil
}

// AuthorizeVoucherForDevice verifies the voucher and atomically binds it to
// the first client MAC address.
//
// This method is intended for the captive-portal "prepare/bind" endpoint
// BEFORE the browser submits credentials to MikroTik.
//
// Rules:
//   - unbound + valid voucher + MAC -> bind and allow
//   - same voucher + same MAC -> allow
//   - same voucher + different MAC -> reject
//   - expired/disabled/invalid status -> reject
//
// The first bind also starts the voucher validity window when StartsAt and
// ExpiresAt have not already been set.
func (s *Service) AuthorizeVoucherForDevice(code, deviceMAC string) (bool, error) {
	_, err := s.BindVoucherToDevice(code, deviceMAC)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, ErrVoucherUnavailable) ||
		errors.Is(err, ErrVoucherExpired) ||
		errors.Is(err, ErrVoucherDataExhausted) ||
		errors.Is(err, ErrVoucherBoundToAnotherDevice) ||
		errors.Is(err, ErrInvalidDeviceMAC) {
		return false, nil
	}

	return false, err
}

// BindVoucherToDevice atomically locks a voucher to one physical client.
//
// It also starts the voucher's validity period on the first successful
// prepare/bind operation and re-syncs FreeRADIUS so Calling-Station-Id is
// enforced before the MikroTik login request is submitted.
func (s *Service) BindVoucherToDevice(code, deviceMAC string) (vouchers.Voucher, error) {
	code = normalizeVoucherCode(code)
	if code == "" {
		return vouchers.Voucher{}, ErrVoucherUnavailable
	}

	mac, err := normalizeMAC(deviceMAC)
	if err != nil {
		return vouchers.Voucher{}, err
	}

	var bound vouchers.Voucher
	var rejectErr error

	err = s.db.Transaction(func(tx *gorm.DB) error {
		var voucher vouchers.Voucher

		if err := tx.
			Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&voucher, "code = ?", code).
			Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrVoucherUnavailable
			}
			return err
		}

		var plan plans.Plan
		if err := tx.First(&plan, "id = ?", voucher.PlanID).Error; err != nil {
			return err
		}
		if !plan.IsActive {
			return ErrVoucherUnavailable
		}

		now := time.Now().UTC()

		if !voucherStatusAllowsLogin(voucher.Status) {
			if err := revokeVoucherRadius(tx, voucher.Code); err != nil {
				return err
			}
			return ErrVoucherUnavailable
		}

		if voucherExpired(voucher, now) {
			if strings.EqualFold(strings.TrimSpace(voucher.Status), "unused") ||
				strings.EqualFold(strings.TrimSpace(voucher.Status), "active") ||
				strings.EqualFold(strings.TrimSpace(voucher.Status), "used") {
				voucher.Status = "expired"
				if err := tx.Save(&voucher).Error; err != nil {
					return err
				}
			}

			if err := revokeVoucherRadius(tx, voucher.Code); err != nil {
				return err
			}
			rejectErr = ErrVoucherExpired
			return nil
		}

		remainingBytes, limited, err := remainingVoucherDataBytes(tx, voucher.Code, plan)
		if err != nil {
			return err
		}
		if limited && remainingBytes <= 0 {
			voucher.Status = "exhausted"
			if err := tx.Save(&voucher).Error; err != nil {
				return err
			}
			if err := revokeVoucherRadius(tx, voucher.Code); err != nil {
				return err
			}
			rejectErr = ErrVoucherDataExhausted
			return nil
		}

		if voucher.DeviceMAC != nil && strings.TrimSpace(*voucher.DeviceMAC) != "" {
			existingMAC, err := normalizeMAC(*voucher.DeviceMAC)
			if err != nil {
				return fmt.Errorf("stored voucher device MAC is invalid: %w", err)
			}

			if existingMAC != mac {
				return ErrVoucherBoundToAnotherDevice
			}
		} else {
			voucher.DeviceMAC = stringPtr(mac)
		}

		// First deliberate Connect attempt starts the voucher's validity period.
		// Manual logout does NOT modify these values.
		if voucher.StartsAt == nil {
			startedAt := now
			voucher.StartsAt = &startedAt
		}
		if voucher.UsedAt == nil {
			usedAt := now
			voucher.UsedAt = &usedAt
		}
		if voucher.ExpiresAt == nil {
			expiresAt := now.Add(time.Duration(max(plan.DurationMinutes, 1)) * time.Minute)
			voucher.ExpiresAt = &expiresAt
		}

		voucher.Status = "active"

		if err := tx.Save(&voucher).Error; err != nil {
			return err
		}

		if _, err := syncVoucherRadiusRecords(tx, voucher, plan, now); err != nil {
			return err
		}

		bound = voucher
		return nil
	})

	if err != nil {
		return vouchers.Voucher{}, err
	}
	if rejectErr != nil {
		return vouchers.Voucher{}, rejectErr
	}

	return bound, nil
}

func (s *Service) SyncVoucher(code string) (VoucherRadiusState, error) {
	code = normalizeVoucherCode(code)
	if code == "" {
		return VoucherRadiusState{}, ErrVoucherUnavailable
	}

	var voucher vouchers.Voucher
	if err := s.db.First(&voucher, "code = ?", code).Error; err != nil {
		return VoucherRadiusState{}, err
	}

	var plan plans.Plan
	if err := s.db.First(&plan, "id = ?", voucher.PlanID).Error; err != nil {
		return VoucherRadiusState{}, err
	}

	if !plan.IsActive {
		return VoucherRadiusState{}, errors.New("plan is inactive")
	}

	now := time.Now().UTC()
	var state VoucherRadiusState

	err := s.db.Transaction(func(tx *gorm.DB) error {
		if voucherExpired(voucher, now) {
			if strings.EqualFold(strings.TrimSpace(voucher.Status), "unused") ||
				strings.EqualFold(strings.TrimSpace(voucher.Status), "active") ||
				strings.EqualFold(strings.TrimSpace(voucher.Status), "used") {

				voucher.Status = "expired"

				if err := tx.Save(&voucher).Error; err != nil {
					return err
				}
			}

			if err := revokeVoucherRadius(tx, voucher.Code); err != nil {
				return err
			}

			state = voucherRadiusState(voucher, plan, now)
			state.Status = "expired"
			state.SessionTimeout = 0
			return nil
		}

		remainingBytes, limited, err := remainingVoucherDataBytes(
			tx,
			voucher.Code,
			plan,
		)
		if err != nil {
			return err
		}

		if limited && remainingBytes <= 0 {
			voucher.Status = "exhausted"

			if err := tx.Save(&voucher).Error; err != nil {
				return err
			}

			if err := revokeVoucherRadius(tx, voucher.Code); err != nil {
				return err
			}

			state = voucherRadiusState(voucher, plan, now)
			state.Status = "exhausted"
			state.SessionTimeout = 0
			return nil
		}

		if !voucherStatusAllowsLogin(voucher.Status) {
			if err := revokeVoucherRadius(tx, voucher.Code); err != nil {
				return err
			}

			state = voucherRadiusState(voucher, plan, now)
			state.SessionTimeout = 0
			return nil
		}

		state, err = syncVoucherRadiusRecords(
			tx,
			voucher,
			plan,
			now,
		)
		return err
	})

	return state, err
}

func syncVoucherRadiusRecords(
	tx *gorm.DB,
	voucher vouchers.Voucher,
	plan plans.Plan,
	now time.Time,
) (VoucherRadiusState, error) {
	state := voucherRadiusState(voucher, plan, now)

	if err := revokeVoucherRadius(tx, voucher.Code); err != nil {
		return VoucherRadiusState{}, err
	}

	// A voucher is intentionally a one-device credential.
	// Calling-Station-Id persists the physical device binding.
	// Port-Limit is returned to MikroTik to limit active sessions without
	// depending on stale FreeRADIUS radacct state.
	checks := []RadCheck{
		{
			Username:  voucher.Code,
			Attribute: "Cleartext-Password",
			Op:        ":=",
			Value:     voucher.Code,
		},
	}

	if mac := strings.TrimSpace(state.DeviceMAC); mac != "" {
		checks = append(checks, RadCheck{
			Username:  voucher.Code,
			Attribute: "Calling-Station-Id",
			Op:        "==",
			Value:     mac,
		})
	}

	replies := []RadReply{
		{
			Username:  voucher.Code,
			Attribute: "Session-Timeout",
			Op:        ":=",
			Value:     fmt.Sprintf("%d", max(state.SessionTimeout, 1)),
		},
		{
			Username:  voucher.Code,
			Attribute: "Port-Limit",
			Op:        ":=",
			Value:     "1",
		},
	}

	// Speed capping is OPTIONAL. If both plan speed fields are blank, no
	// Mikrotik-Rate-Limit attribute is returned and RouterOS keeps the default
	// unlimited profile behavior.
	if state.RateLimit != "" {
		replies = append(replies, RadReply{
			Username:  voucher.Code,
			Attribute: "Mikrotik-Rate-Limit",
			Op:        ":=",
			Value:     state.RateLimit,
		})
	}

	// Data capping is OPTIONAL and PERSISTENT across reconnects. We subtract
	// already-accounted input+output bytes from the package allowance and only
	// return the remaining bytes to RouterOS for the next session.
	remainingBytes, limited, err := remainingVoucherDataBytes(tx, voucher.Code, plan)
	if err != nil {
		return VoucherRadiusState{}, err
	}
	if limited {
		if remainingBytes <= 0 {
			return VoucherRadiusState{}, ErrVoucherDataExhausted
		}
		replies = appendMikrotikTotalLimit(replies, voucher.Code, remainingBytes)
	}

	if err := tx.Create(&checks).Error; err != nil {
		return VoucherRadiusState{}, err
	}
	if err := tx.Create(&replies).Error; err != nil {
		return VoucherRadiusState{}, err
	}

	return state, nil
}

func revokeVoucherRadius(tx *gorm.DB, code string) error {
	if err := tx.Where("username = ?", code).Delete(&RadCheck{}).Error; err != nil {
		return err
	}
	return tx.Where("username = ?", code).Delete(&RadReply{}).Error
}

func voucherRadiusState(
	voucher vouchers.Voucher,
	plan plans.Plan,
	now time.Time,
) VoucherRadiusState {
	deviceMAC := ""

	if voucher.DeviceMAC != nil {
		if normalized, err := normalizeMAC(*voucher.DeviceMAC); err == nil {
			deviceMAC = normalized
		}
	}

	return VoucherRadiusState{
		Username:       voucher.Code,
		Status:         normalizeVoucherStatus(voucher.Status),
		SessionTimeout: remainingVoucherSeconds(voucher, plan, now),
		RateLimit:      mikrotikRateLimit(plan.UploadSpeed, plan.DownloadSpeed),
		MaxDevices:     1,
		DeviceMAC:      deviceMAC,
	}
}

func remainingVoucherSeconds(
	voucher vouchers.Voucher,
	plan plans.Plan,
	now time.Time,
) int {
	fullDuration := max(plan.DurationMinutes, 1) * 60

	if voucher.ExpiresAt == nil {
		return fullDuration
	}

	remaining := voucher.ExpiresAt.Sub(now)
	if remaining <= 0 {
		return 0
	}

	seconds := int((remaining + time.Second - 1) / time.Second)
	if seconds > fullDuration {
		return fullDuration
	}

	return max(seconds, 1)
}

func (s *Service) SyncVoucherForVoucher(code string) error {
	_, err := s.SyncVoucher(code)
	return err
}

func (s *Service) SyncAllVouchers() (int, error) {
	var items []vouchers.Voucher
	if err := s.db.Find(&items).Error; err != nil {
		return 0, err
	}

	count := 0
	for _, voucher := range items {
		if _, err := s.SyncVoucher(voucher.Code); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}

func (s *Service) SyncAllPlans() (int, error) {
	var items []plans.Plan
	if err := s.db.Find(&items).Error; err != nil {
		return 0, err
	}

	count := 0
	for _, plan := range items {
		if err := s.syncPlan(plan); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}

func (s *Service) syncPlan(plan plans.Plan) error {
	if plan.ID == uuid.Nil {
		return nil
	}

	updates := []RadGroupReply{
		{
			GroupName: plan.ID.String(),
			Attribute: "Session-Timeout",
			Op:        ":=",
			Value:     fmt.Sprintf("%d", max(plan.DurationMinutes, 1)*60),
		},
	}

	if rateLimit := mikrotikRateLimit(plan.UploadSpeed, plan.DownloadSpeed); rateLimit != "" {
		updates = append(updates, RadGroupReply{
			GroupName: plan.ID.String(),
			Attribute: "Mikrotik-Rate-Limit",
			Op:        ":=",
			Value:     rateLimit,
		})
	}

	if plan.DataLimitMB != nil && *plan.DataLimitMB > 0 {
		updates = append(updates, RadGroupReply{
			GroupName: plan.ID.String(),
			Attribute: "Mikrotik-Total-Limit",
			Op:        ":=",
			Value:     fmt.Sprintf("%d", int64(*plan.DataLimitMB)*1024*1024),
		})
	}

	updates = append(updates, RadGroupReply{
		GroupName: plan.ID.String(),
		Attribute: "Port-Limit",
		Op:        ":=",
		Value:     fmt.Sprintf("%d", max(plan.MaxDevices, 1)),
	})

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Where("groupname = ?", plan.ID.String()).
			Delete(&RadGroupReply{}).
			Error; err != nil {
			return err
		}

		// Remove old Simultaneous-Use group checks. Stale radacct rows can make
		// FreeRADIUS reject a legitimate reconnect after a manual HotSpot logout.
		// MikroTik Port-Limit is used instead for active-session concurrency.
		if err := tx.
			Where("groupname = ?", plan.ID.String()).
			Delete(&RadGroupCheck{}).
			Error; err != nil {
			return err
		}

		return tx.Create(&updates).Error
	})
}

// voucherUsageState is retained for compatibility with the existing
// accounting-consumption hook.
//
// IMPORTANT: older code returned "used". AuthorizeVoucher did not accept
// "used", which made the voucher effectively one-shot. The correct state
// after first successful use is "active".
func voucherUsageState(
	status string,
	usedAt *time.Time,
	now time.Time,
) (string, *time.Time) {
	switch normalizeVoucherStatus(status) {
	case "unused", "active":
		if usedAt == nil {
			value := now.UTC()
			usedAt = &value
		}
		return "active", usedAt
	default:
		return strings.TrimSpace(status), usedAt
	}
}

func normalizeVoucherStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))

	switch status {
	case "used":
		// Legacy value from the previous consumption hook.
		return "active"
	default:
		return status
	}
}

func voucherStatusAllowsLogin(status string) bool {
	switch normalizeVoucherStatus(status) {
	case "unused", "active":
		return true
	default:
		return false
	}
}

func voucherExpired(voucher vouchers.Voucher, now time.Time) bool {
	return voucher.ExpiresAt != nil && !voucher.ExpiresAt.After(now)
}

func normalizeVoucherCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

func normalizeMAC(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return "", ErrInvalidDeviceMAC
	}

	var hex strings.Builder
	hex.Grow(12)

	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			hex.WriteRune(r)
		case r >= 'A' && r <= 'F':
			hex.WriteRune(r)
		case r == ':' || r == '-' || r == '.' || r == ' ':
			continue
		default:
			return "", ErrInvalidDeviceMAC
		}
	}

	raw := hex.String()
	if len(raw) != 12 {
		return "", ErrInvalidDeviceMAC
	}

	parts := make([]string, 0, 6)
	for i := 0; i < 12; i += 2 {
		parts = append(parts, raw[i:i+2])
	}

	return strings.Join(parts, ":"), nil
}

func stringPtr(value string) *string {
	return &value
}

func (s *Service) AccountingSummary() (map[string]any, error) {
	var active int64
	if err := s.db.
		Model(&RadAcct{}).
		Where("acctstoptime IS NULL").
		Count(&active).
		Error; err != nil {
		return nil, err
	}

	var totals struct {
		Input  int64
		Output int64
	}

	if err := s.db.
		Model(&RadAcct{}).
		Select(
			"COALESCE(SUM(acctinputoctets),0) as input, " +
				"COALESCE(SUM(acctoutputoctets),0) as output",
		).
		Scan(&totals).
		Error; err != nil {
		return nil, err
	}

	return map[string]any{
		"active_sessions": active,
		"upload_bytes":    totals.Input,
		"download_bytes":  totals.Output,
	}, nil
}

// mikrotikRateLimit returns an OPTIONAL RouterOS rate limit.
//
// RouterOS interprets rx/tx from the router's point of view, which means the
// first value is client upload and the second value is client download.
//
// Both fields blank => no speed cap.
// One field blank => mirror the configured value to the other direction. This
// avoids silently inventing a NobliFi default speed while still producing a
// valid two-direction cap for partially populated legacy plans.
func mikrotikRateLimit(uploadSpeed, downloadSpeed string) string {
	upload := strings.TrimSpace(uploadSpeed)
	download := strings.TrimSpace(downloadSpeed)

	if upload == "" && download == "" {
		return ""
	}
	if upload == "" {
		upload = download
	}
	if download == "" {
		download = upload
	}

	return upload + "/" + download
}

// remainingVoucherDataBytes returns the amount of the optional plan allowance
// that has not yet been accounted for in radacct.
//
// The allowance is cumulative across sessions because accounting rows are
// summed by voucher username. A manual logout therefore cannot reset the cap.
func remainingVoucherDataBytes(
	tx *gorm.DB,
	username string,
	plan plans.Plan,
) (int64, bool, error) {
	if plan.DataLimitMB == nil || *plan.DataLimitMB <= 0 {
		return 0, false, nil
	}

	limitBytes := int64(*plan.DataLimitMB) * 1024 * 1024

	var totals struct {
		Input  int64
		Output int64
	}

	if err := tx.
		Model(&RadAcct{}).
		Where("username = ?", username).
		Select(
			"COALESCE(SUM(acctinputoctets),0) AS input, " +
				"COALESCE(SUM(acctoutputoctets),0) AS output",
		).
		Scan(&totals).
		Error; err != nil {
		return 0, true, err
	}

	return limitBytes - (totals.Input + totals.Output), true, nil
}

// appendMikrotikTotalLimit supports allowances above 4GiB using MikroTik's
// Total-Limit-Gigawords companion attribute.
func appendMikrotikTotalLimit(
	replies []RadReply,
	username string,
	bytes int64,
) []RadReply {
	if bytes <= 0 {
		return replies
	}

	value := uint64(bytes)
	low := uint32(value & 0xffffffff)
	high := uint32(value >> 32)

	replies = append(replies, RadReply{
		Username:  username,
		Attribute: "Mikrotik-Total-Limit",
		Op:        ":=",
		Value:     fmt.Sprintf("%d", low),
	})

	if high > 0 {
		replies = append(replies, RadReply{
			Username:  username,
			Attribute: "Mikrotik-Total-Limit-Gigawords",
			Op:        ":=",
			Value:     fmt.Sprintf("%d", high),
		})
	}

	return replies
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
