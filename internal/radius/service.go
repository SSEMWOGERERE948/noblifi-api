package radius

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/placeholders"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

// RadAcct represents a minimal subset of the radacct table used by the
// accounting summary queries in this service.
type RadAcct struct {
	AcctStopTime     *time.Time `gorm:"column:acctstoptime"`
	AcctInputOctets  int64      `gorm:"column:acctinputoctets"`
	AcctOutputOctets int64      `gorm:"column:acctoutputoctets"`
}

type VoucherRadiusState struct {
	Username       string `json:"username"`
	Status         string `json:"status"`
	Authorized     bool   `json:"authorized"`
	SessionTimeout int    `json:"session_timeout"`
	RateLimit      string `json:"rate_limit"`
	MaxDevices     int    `json:"max_devices"`
	RadiusGroup    string `json:"radius_group"`
}

type NAS struct {
	NASName     string
	ShortName   string
	Type        string
	Secret      string
	Description string
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// ---------------------------------------------------------
// NAS
// ---------------------------------------------------------

func (s *Service) RegisterNAS(
	nasName string,
	shortName string,
	secret string,
	description string,
) error {
	nasName = strings.TrimSpace(nasName)
	if nasName == "" {
		return nil
	}

	shortName = strings.TrimSpace(shortName)
	if shortName == "" {
		shortName = nasName
	}

	secret = strings.TrimSpace(secret)
	if secret == "" || placeholders.Is(secret) {
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

// ---------------------------------------------------------
// PLAN / PACKAGE RADIUS POLICY
// ---------------------------------------------------------

func (s *Service) SyncPlanForRadius(plan plans.Plan) error {
	if plan.ID == uuid.Nil {
		return errors.New("cannot sync RADIUS plan without plan ID")
	}

	groupName := radiusGroupName(plan.ID)

	return s.db.Transaction(func(tx *gorm.DB) error {
		// Rebuild the policy every time so package updates do not leave
		// stale RADIUS attributes behind.
		if err := tx.
			Where("groupname = ?", groupName).
			Delete(&RadGroupCheck{}).Error; err != nil {
			return err
		}

		if err := tx.
			Where("groupname = ?", groupName).
			Delete(&RadGroupReply{}).Error; err != nil {
			return err
		}

		// An inactive plan should no longer have an active RADIUS policy.
		if !plan.IsActive {
			return nil
		}

		if plan.DurationMinutes <= 0 {
			return fmt.Errorf(
				"plan %s has invalid duration_minutes=%d",
				plan.ID,
				plan.DurationMinutes,
			)
		}

		maxDevices := plan.MaxDevices
		if maxDevices <= 0 {
			maxDevices = 1
		}

		sessionSeconds := plan.DurationMinutes * 60

		replies := []RadGroupReply{
			{
				GroupName: groupName,
				Attribute: "Session-Timeout",
				Op:        ":=",
				Value:     strconv.Itoa(sessionSeconds),
			},
			{
				GroupName: groupName,
				Attribute: "Mikrotik-Rate-Limit",
				Op:        ":=",
				Value: mikrotikRateLimit(
					plan.UploadSpeed,
					plan.DownloadSpeed,
				),
			},
			{
				GroupName: groupName,
				Attribute: "Port-Limit",
				Op:        ":=",
				Value:     strconv.Itoa(maxDevices),
			},
		}

		// Optional total data allowance.
		//
		// MikroTik Total-Limit consists of a low 32-bit value plus an
		// optional Gigawords value for the upper 32 bits.
		if plan.DataLimitMB != nil && *plan.DataLimitMB > 0 {
			totalBytes := uint64(*plan.DataLimitMB) * 1024 * 1024

			low := uint32(totalBytes & 0xffffffff)
			high := uint32(totalBytes >> 32)

			replies = append(replies, RadGroupReply{
				GroupName: groupName,
				Attribute: "Mikrotik-Total-Limit",
				Op:        ":=",
				Value:     strconv.FormatUint(uint64(low), 10),
			})

			if high > 0 {
				replies = append(replies, RadGroupReply{
					GroupName: groupName,
					Attribute: "Mikrotik-Total-Limit-Gigawords",
					Op:        ":=",
					Value:     strconv.FormatUint(uint64(high), 10),
				})
			}
		}

		return tx.Create(&replies).Error
	})
}

func (s *Service) SyncAllPlans() (int, error) {
	var items []plans.Plan

	if err := s.db.Find(&items).Error; err != nil {
		return 0, err
	}

	count := 0

	for _, plan := range items {
		if err := s.SyncPlanForRadius(plan); err != nil {
			return count, fmt.Errorf(
				"sync plan %s: %w",
				plan.ID,
				err,
			)
		}

		count++
	}

	return count, nil
}

// ---------------------------------------------------------
// VOUCHERS
// ---------------------------------------------------------

func (s *Service) AuthorizeVoucher(code string) (bool, error) {
	voucher, plan, err := s.voucherPlan(strings.TrimSpace(code))
	if err != nil {
		return false, err
	}

	if !plan.IsActive {
		return false, nil
	}

	return voucherUsable(voucher), nil
}

func (s *Service) SyncVoucher(code string) (VoucherRadiusState, error) {
	code = strings.TrimSpace(code)

	if code == "" {
		return VoucherRadiusState{}, errors.New("voucher code is required")
	}

	var voucher vouchers.Voucher

	if err := s.db.
		First(&voucher, "code = ?", code).
		Error; err != nil {
		return VoucherRadiusState{}, err
	}

	var plan plans.Plan

	if err := s.db.
		First(&plan, "id = ?", voucher.PlanID).
		Error; err != nil {
		return VoucherRadiusState{}, err
	}

	groupName := radiusGroupName(plan.ID)

	state := VoucherRadiusState{
		Username:       voucher.Code,
		Status:         voucher.Status,
		Authorized:     voucherUsable(voucher) && plan.IsActive,
		SessionTimeout: plan.DurationMinutes * 60,
		RateLimit: mikrotikRateLimit(
			plan.UploadSpeed,
			plan.DownloadSpeed,
		),
		MaxDevices:  maxInt(plan.MaxDevices, 1),
		RadiusGroup: groupName,
	}

	// Always ensure the package policy exists before associating
	// a voucher with the package.
	if err := s.SyncPlanForRadius(plan); err != nil {
		return state, fmt.Errorf(
			"sync RADIUS package %s: %w",
			plan.ID,
			err,
		)
	}

	err := s.db.Transaction(func(tx *gorm.DB) error {
		// Remove all previous authentication and group information.
		if err := tx.
			Where("username = ?", voucher.Code).
			Delete(&RadCheck{}).Error; err != nil {
			return err
		}

		if err := tx.
			Where("username = ?", voucher.Code).
			Delete(&RadReply{}).Error; err != nil {
			return err
		}

		if err := tx.
			Where("username = ?", voucher.Code).
			Delete(&RadUserGroup{}).Error; err != nil {
			return err
		}

		// Expired, used, cancelled, etc. vouchers are deliberately left
		// without a radcheck password. FreeRADIUS therefore cannot
		// authenticate them.
		//
		// This is a normal, expected outcome for unusable/inactive
		// vouchers - but it used to be completely silent, which made it
		// indistinguishable from a real bug when someone found a voucher
		// missing from radcheck. Log it so that distinction is obvious
		// immediately instead of requiring a manual DB investigation.
		if !state.Authorized {
			log.Printf(
				"radius sync skipped for voucher %s: not authorized (voucher_status=%s, plan_active=%t, plan_id=%s)",
				voucher.Code,
				voucher.Status,
				plan.IsActive,
				plan.ID,
			)

			return nil
		}

		// NobliFi is a single-code voucher system:
		//
		// username = NF-xxxxxxxx
		// password = NF-xxxxxxxx
		//
		// MikroTik sends the same value for both fields.
		if err := tx.Create(&RadCheck{
			Username:  voucher.Code,
			Attribute: "Cleartext-Password",
			Op:        ":=",
			Value:     voucher.Code,
		}).Error; err != nil {
			return err
		}

		// Ensure SQL group processing continues after the password
		// check so the package attributes are applied.
		if err := tx.Create(&RadReply{
			Username:  voucher.Code,
			Attribute: "Fall-Through",
			Op:        "=",
			Value:     "Yes",
		}).Error; err != nil {
			return err
		}

		// Attach this voucher to its RADIUS package.
		if err := tx.Create(&RadUserGroup{
			Username:  voucher.Code,
			GroupName: groupName,
			Priority:  1,
		}).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Printf(
			"radius sync failed for voucher %s: %v",
			voucher.Code,
			err,
		)
	}

	return state, err
}

// Keep this signature because your vouchers.Service already expects it.
func (s *Service) SyncVoucherForVoucher(code string) error {
	_, err := s.SyncVoucher(code)
	return err
}

func (s *Service) SyncAllVouchers() (int, error) {
	// Package/group policies must exist first.
	if _, err := s.SyncAllPlans(); err != nil {
		return 0, err
	}

	var items []vouchers.Voucher

	if err := s.db.Find(&items).Error; err != nil {
		return 0, err
	}

	count := 0

	for _, voucher := range items {
		if _, err := s.SyncVoucher(voucher.Code); err != nil {
			return count, fmt.Errorf(
				"sync voucher %s: %w",
				voucher.Code,
				err,
			)
		}

		count++
	}

	return count, nil
}

// ---------------------------------------------------------
// ACCOUNTING
// ---------------------------------------------------------

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
		Select(`
			COALESCE(SUM(acctinputoctets), 0) AS input,
			COALESCE(SUM(acctoutputoctets), 0) AS output
		`).
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

// ---------------------------------------------------------
// HELPERS
// ---------------------------------------------------------

func (s *Service) voucherPlan(
	code string,
) (vouchers.Voucher, plans.Plan, error) {
	var voucher vouchers.Voucher

	if err := s.db.
		First(&voucher, "code = ?", code).
		Error; err != nil {
		return voucher, plans.Plan{}, err
	}

	var plan plans.Plan

	if err := s.db.
		First(&plan, "id = ?", voucher.PlanID).
		Error; err != nil {
		return voucher, plan, err
	}

	return voucher, plan, nil
}

func voucherUsable(voucher vouchers.Voucher) bool {
	switch voucher.Status {
	case "unused", "active":
	default:
		return false
	}

	if voucher.ExpiresAt != nil &&
		!voucher.ExpiresAt.After(time.Now()) {
		return false
	}

	return true
}

func (s *Service) markVoucherUsed(code string, status string, usedAt *time.Time) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil
	}

	now := time.Now().UTC()
	newStatus, newUsedAt := voucherUsageState(status, usedAt, now)
	if strings.EqualFold(newStatus, status) && usedAt != nil && newUsedAt != nil && newUsedAt.Equal(*usedAt) {
		return nil
	}

	return s.db.Model(&vouchers.Voucher{}).
		Where("code = ?", code).
		Updates(map[string]any{
			"status":  newStatus,
			"used_at": newUsedAt,
		}).Error
}

func voucherUsageState(status string, usedAt *time.Time, now time.Time) (string, *time.Time) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "used":
		return "used", usedAt
	case "", "unused", "active":
		if usedAt != nil {
			return "used", usedAt
		}
		return "used", &now
	default:
		return status, usedAt
	}
}

func radiusGroupName(planID uuid.UUID) string {
	return "plan-" + planID.String()
}

func mikrotikRateLimit(
	uploadSpeed string,
	downloadSpeed string,
) string {
	upload := normalizeRate(uploadSpeed, "2M")
	download := normalizeRate(downloadSpeed, "5M")

	// MikroTik defines the first value as router RX,
	// i.e. client upload, and the second as router TX,
	// i.e. client download.
	return upload + "/" + download
}

func normalizeRate(value, fallback string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, " ", "")

	if value == "" {
		return fallback
	}

	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
