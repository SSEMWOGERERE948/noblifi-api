package radius

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/gorm"
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
	if secret == "" || secret == "CHANGE_ME_RADIUS_SECRET" {
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
func (s *Service) AuthorizeVoucher(code string) (bool, error) {
	var voucher vouchers.Voucher
	if err := s.db.First(&voucher, "code = ?", strings.TrimSpace(code)).Error; err != nil {
		return false, err
	}
	if voucher.Status != "unused" && voucher.Status != "active" {
		return false, nil
	}
	now := time.Now()
	if voucher.ExpiresAt != nil && voucher.ExpiresAt.Before(now) {
		return false, nil
	}
	return true, nil
}

func (s *Service) SyncVoucher(code string) (VoucherRadiusState, error) {
	var voucher vouchers.Voucher
	if err := s.db.First(&voucher, "code = ?", strings.TrimSpace(code)).Error; err != nil {
		return VoucherRadiusState{}, err
	}

	var plan plans.Plan
	if err := s.db.First(&plan, "id = ?", voucher.PlanID).Error; err != nil {
		return VoucherRadiusState{}, err
	}
	if !plan.IsActive {
		return VoucherRadiusState{}, errors.New("plan is inactive")
	}

	state := VoucherRadiusState{
		Username:       voucher.Code,
		Status:         voucher.Status,
		SessionTimeout: plan.DurationMinutes * 60,
		RateLimit:      mikrotikRateLimit(plan.UploadSpeed, plan.DownloadSpeed),
		MaxDevices:     plan.MaxDevices,
	}

	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("username = ?", voucher.Code).Delete(&RadCheck{}).Error; err != nil {
			return err
		}
		if err := tx.Where("username = ?", voucher.Code).Delete(&RadReply{}).Error; err != nil {
			return err
		}
		checks := []RadCheck{
			{Username: voucher.Code, Attribute: "Cleartext-Password", Op: ":=", Value: voucher.Code},
			{Username: voucher.Code, Attribute: "Simultaneous-Use", Op: ":=", Value: fmt.Sprintf("%d", max(plan.MaxDevices, 1))},
		}
		replies := []RadReply{
			{Username: voucher.Code, Attribute: "Session-Timeout", Op: ":=", Value: fmt.Sprintf("%d", state.SessionTimeout)},
			{Username: voucher.Code, Attribute: "Mikrotik-Rate-Limit", Op: ":=", Value: state.RateLimit},
		}
		if plan.DataLimitMB != nil && *plan.DataLimitMB > 0 {
			replies = append(replies, RadReply{
				Username:  voucher.Code,
				Attribute: "Mikrotik-Total-Limit",
				Op:        ":=",
				Value:     fmt.Sprintf("%d", int64(*plan.DataLimitMB)*1024*1024),
			})
		}
		if err := tx.Create(&checks).Error; err != nil {
			return err
		}
		return tx.Create(&replies).Error
	})
	return state, err
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

func (s *Service) AccountingSummary() (map[string]any, error) {
	var active int64
	if err := s.db.Model(&RadAcct{}).Where("acctstoptime IS NULL").Count(&active).Error; err != nil {
		return nil, err
	}
	var totals struct {
		Input  int64
		Output int64
	}
	if err := s.db.Model(&RadAcct{}).Select("COALESCE(SUM(acctinputoctets),0) as input, COALESCE(SUM(acctoutputoctets),0) as output").Scan(&totals).Error; err != nil {
		return nil, err
	}
	return map[string]any{
		"active_sessions": active,
		"upload_bytes":    totals.Input,
		"download_bytes":  totals.Output,
	}, nil
}

func mikrotikRateLimit(uploadSpeed, downloadSpeed string) string {
	upload := strings.TrimSpace(uploadSpeed)
	download := strings.TrimSpace(downloadSpeed)
	if upload == "" {
		upload = "2M"
	}
	if download == "" {
		download = "5M"
	}
	return upload + "/" + download
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
