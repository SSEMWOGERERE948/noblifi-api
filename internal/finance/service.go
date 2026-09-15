package finance

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/database"
	"github.com/noblifi/noblifi/backend/internal/payments"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	withdrawalCodeTTL     = 15 * time.Minute
	purposeWithdrawalCode = "wallet_withdrawal"
)

type RadiusSyncer interface {
	SyncVoucherForVoucher(code string) error
}

type PayoutProvider interface {
	InitiatePayout(input payments.PayoutRequest) (payments.PayoutResult, error)
	CheckPayoutStatus(transactionID string) (payments.PayoutResult, error)
}

type Service struct {
	db             *gorm.DB
	cfg            config.Config
	radius         RadiusSyncer
	payoutProvider PayoutProvider
}

func NewService(db *gorm.DB, cfg config.Config, radius RadiusSyncer) *Service {
	return &Service{db: db, cfg: cfg, radius: radius}
}

func (s *Service) SetPayoutProvider(provider PayoutProvider) {
	s.payoutProvider = provider
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&Sale{}, &Wallet{}, &WalletTransaction{}, &Withdrawal{}, &FinanceActionLog{})
}

type Scope struct {
	UserID       uuid.UUID
	IsSuperadmin bool
}

type SettlementResult struct {
	VoucherCode string
	SaleID      uuid.UUID
}

func CalculateCommission(source string, grossAmount int64, commissionBPS int) (int64, int64, error) {
	if grossAmount <= 0 {
		return 0, 0, errors.New("gross amount must be greater than zero")
	}
	if commissionBPS < 0 {
		return 0, 0, errors.New("commission bps cannot be negative")
	}
	platformFee := int64(0)
	if source == SaleSourceMobileMoney {
		platformFee = grossAmount * int64(commissionBPS) / 10000
	}
	if platformFee > grossAmount {
		return 0, 0, errors.New("platform fee cannot exceed gross amount")
	}
	return platformFee, grossAmount - platformFee, nil
}

func (s *Service) SettlePaidHotspotPurchase(purchaseID uuid.UUID) (payments.HotspotSettlementResult, error) {
	result, err := s.settlePaidHotspotPurchase(purchaseID)
	if err != nil {
		return payments.HotspotSettlementResult{}, err
	}
	return payments.HotspotSettlementResult{VoucherCode: result.VoucherCode}, nil
}

func (s *Service) settlePaidHotspotPurchase(purchaseID uuid.UUID) (SettlementResult, error) {
	var result SettlementResult
	var voucherCode string
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var purchase payments.HotspotPurchase
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&purchase, "id = ?", purchaseID).Error; err != nil {
			return err
		}
		if purchase.Status != "paid" {
			return errors.New("purchase is not paid")
		}
		if purchase.PaidAt == nil {
			now := time.Now()
			purchase.PaidAt = &now
			if err := tx.Model(&payments.HotspotPurchase{}).Where("id = ?", purchase.ID).Update("paid_at", now).Error; err != nil {
				return err
			}
		}

		voucher, err := s.ensureOnlineVoucher(tx, &purchase)
		if err != nil {
			return err
		}
		voucherCode = voucher.Code

		sale, err := s.ensureOnlineSale(tx, purchase, voucher)
		if err != nil {
			return err
		}
		result.SaleID = sale.ID
		return nil
	})
	if err != nil {
		return result, err
	}
	if s.radius != nil && voucherCode != "" {
		if err := s.radius.SyncVoucherForVoucher(voucherCode); err != nil {
			return result, fmt.Errorf("hotspot voucher created but RADIUS sync failed: %w", err)
		}
	}
	result.VoucherCode = voucherCode
	return result, nil
}

func (s *Service) ensureOnlineVoucher(tx *gorm.DB, purchase *payments.HotspotPurchase) (vouchers.Voucher, error) {
	var voucher vouchers.Voucher
	if purchase.VoucherID != nil {
		if err := tx.First(&voucher, "id = ?", *purchase.VoucherID).Error; err == nil {
			return voucher, nil
		}
	}
	if err := tx.First(&voucher, "purchase_id = ?", purchase.ID).Error; err == nil {
		purchase.VoucherID = &voucher.ID
		_ = tx.Model(&payments.HotspotPurchase{}).Where("id = ?", purchase.ID).Update("voucher_id", voucher.ID).Error
		return voucher, nil
	}
	code := strings.TrimSpace(firstNonEmpty(purchase.LocalTransactionID, purchase.OrderTrackingID, purchase.MerchantReference))
	if code == "" {
		return voucher, errors.New("paid hotspot purchase has no transaction id")
	}

	ownerID := purchase.OwnerUserID
	routerID := purchase.RouterID
	purchaseID := purchase.ID
	mac := purchase.DeviceMAC
	voucher = vouchers.Voucher{
		ID: uuid.New(), UserID: &ownerID, Code: code,
		PlanID: purchase.PlanID, Channel: vouchers.VoucherChannelOnline, RouterID: &routerID,
		PurchaseID: &purchaseID, DeviceMAC: &mac, Status: "unused",
	}
	if err := tx.Create(&voucher).Error; err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			if err := tx.First(&voucher, "code = ?", code).Error; err == nil && voucher.PurchaseID != nil && *voucher.PurchaseID == purchase.ID {
				purchase.VoucherID = &voucher.ID
				_ = tx.Model(&payments.HotspotPurchase{}).Where("id = ?", purchase.ID).Update("voucher_id", voucher.ID).Error
				return voucher, nil
			}
		}
		return voucher, err
	}
	purchase.VoucherID = &voucher.ID
	if err := tx.Model(&payments.HotspotPurchase{}).Where("id = ?", purchase.ID).Updates(map[string]any{
		"voucher_id": voucher.ID,
		"status":     "paid",
	}).Error; err != nil {
		return voucher, err
	}
	return voucher, nil
}

func (s *Service) ensureOnlineSale(tx *gorm.DB, purchase payments.HotspotPurchase, voucher vouchers.Voucher) (Sale, error) {
	var existing Sale
	if err := tx.First(&existing, "hotspot_purchase_id = ?", purchase.ID).Error; err == nil {
		customerName := strings.TrimSpace(purchase.CustomerName)
		if customerName != "" && customerName != purchase.Phone && (strings.TrimSpace(existing.CustomerName) == "" || existing.CustomerName == purchase.Phone) {
			_ = tx.Model(&Sale{}).Where("id = ?", existing.ID).Update("customer_name", customerName).Error
			existing.CustomerName = customerName
		}
		return existing, nil
	}
	platformFee, merchantNet, err := CalculateCommission(SaleSourceMobileMoney, int64(purchase.Amount), s.cfg.MobileMoneyCommissionBPS)
	if err != nil {
		return Sale{}, err
	}
	routerID := purchase.RouterID
	purchaseID := purchase.ID
	soldAt := time.Now()
	if purchase.PaidAt != nil {
		soldAt = *purchase.PaidAt
	}
	sale := Sale{
		OwnerUserID: purchase.OwnerUserID, RouterID: &routerID, PlanID: purchase.PlanID, VoucherID: voucher.ID,
		HotspotPurchaseID: &purchaseID, Source: SaleSourceMobileMoney, CustomerName: purchase.CustomerName,
		Phone: purchase.Phone, GrossAmount: int64(purchase.Amount), CommissionRateBPS: s.cfg.MobileMoneyCommissionBPS,
		PlatformFeeAmount: platformFee, MerchantNetAmount: merchantNet, Currency: purchase.Currency,
		PaymentProvider: purchase.Provider, PaymentReference: firstNonEmpty(purchase.LocalTransactionID, purchase.OrderTrackingID, purchase.MerchantReference),
		PaymentStatus: "paid", SoldAt: soldAt,
	}
	if err := tx.Create(&sale).Error; err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			if err := tx.First(&existing, "hotspot_purchase_id = ?", purchase.ID).Error; err == nil {
				return existing, nil
			}
		}
		return Sale{}, err
	}
	merchantWallet, err := s.walletForMerchant(tx, purchase.OwnerUserID, purchase.Currency)
	if err != nil {
		return Sale{}, err
	}
	platformWallet, err := s.platformWallet(tx, purchase.Currency)
	if err != nil {
		return Sale{}, err
	}
	if merchantNet > 0 {
		if err := s.createLedger(tx, merchantWallet, &purchase.OwnerUserID, LedgerTypeSaleCredit, LedgerDirectionCredit, merchantNet, purchase.Currency, "sale", sale.ID, "Merchant net online sale credit", "sale-credit-"+sale.ID.String()); err != nil {
			return Sale{}, err
		}
	}
	if platformFee > 0 {
		if err := s.createLedger(tx, platformWallet, nil, LedgerTypePlatformCommission, LedgerDirectionCredit, platformFee, purchase.Currency, "sale", sale.ID, "NobliFi online sale commission", "platform-commission-"+sale.ID.String()); err != nil {
			return Sale{}, err
		}
	}
	return sale, nil
}

type RecordPhysicalSaleInput struct {
	VoucherID       uuid.UUID
	Amount          int64
	CustomerName    string
	Phone           string
	RouterID        *uuid.UUID
	CreatedByUserID uuid.UUID
}

func (s *Service) RecordPhysicalSale(scope Scope, input RecordPhysicalSaleInput) (Sale, error) {
	var sale Sale
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var voucher vouchers.Voucher
		query := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&voucher, "id = ?", input.VoucherID)
		if err := query.Error; err != nil {
			return err
		}
		if !scope.IsSuperadmin {
			if voucher.UserID == nil || *voucher.UserID != scope.UserID {
				return gorm.ErrRecordNotFound
			}
		}
		if voucher.Channel != vouchers.VoucherChannelPhysical {
			return errors.New("only physical vouchers can be manually marked sold")
		}
		var existing Sale
		if err := tx.First(&existing, "voucher_id = ?", voucher.ID).Error; err == nil {
			return errors.New("voucher has already been recorded as sold")
		}
		if input.Amount <= 0 {
			return errors.New("sale amount must be greater than zero")
		}
		ownerID := scope.UserID
		if voucher.UserID != nil {
			ownerID = *voucher.UserID
		}
		platformFee, merchantNet, err := CalculateCommission(SaleSourcePhysical, input.Amount, 0)
		if err != nil {
			return err
		}
		sale = Sale{
			OwnerUserID: ownerID, RouterID: input.RouterID, PlanID: voucher.PlanID, VoucherID: voucher.ID,
			Source: SaleSourcePhysical, CustomerName: strings.TrimSpace(input.CustomerName), Phone: strings.TrimSpace(input.Phone),
			GrossAmount: input.Amount, CommissionRateBPS: 0, PlatformFeeAmount: platformFee, MerchantNetAmount: merchantNet,
			Currency: "UGX", PaymentStatus: "paid", SoldAt: time.Now(), CreatedByUserID: &input.CreatedByUserID,
		}
		if err := tx.Create(&sale).Error; err != nil {
			return err
		}
		return tx.Model(&vouchers.Voucher{}).Where("id = ?", voucher.ID).Update("status", "sold").Error
	})
	return sale, err
}

type WalletSummary struct {
	Currency           string `json:"currency"`
	Available          int64  `json:"available"`
	TotalCredits       int64  `json:"total_credits"`
	TotalDebits        int64  `json:"total_debits"`
	PendingWithdrawals int64  `json:"pending_withdrawals"`
}

type WithdrawalCodeDelivery struct {
	Sent        bool      `json:"sent"`
	DevCode     string    `json:"dev_code,omitempty"`
	Message     string    `json:"message"`
	SMTPEnabled bool      `json:"smtp_enabled"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type WithdrawalRecipient struct {
	Destination string `json:"destination"`
	AccountName string `json:"account_name"`
	Known       bool   `json:"known"`
	Verified    bool   `json:"verified"`
	Source      string `json:"source"`
}

type withdrawalCodePayload struct {
	Amount      int64  `json:"amount"`
	Destination string `json:"destination"`
}

func (s *Service) WalletSummary(scope Scope) (WalletSummary, error) {
	wallet, err := s.walletForMerchant(s.db, scope.UserID, "UGX")
	if err != nil {
		return WalletSummary{}, err
	}
	return s.walletSummary(wallet.ID, "UGX")
}

func (s *Service) walletSummary(walletID uuid.UUID, currency string) (WalletSummary, error) {
	return s.walletSummaryFromDB(s.db, walletID, currency)
}

func (s *Service) walletSummaryFromDB(db *gorm.DB, walletID uuid.UUID, currency string) (WalletSummary, error) {
	var credits, debits, pending int64
	if err := db.Model(&WalletTransaction{}).Where("wallet_id = ? AND direction = ?", walletID, LedgerDirectionCredit).Select("COALESCE(SUM(amount), 0)").Scan(&credits).Error; err != nil {
		return WalletSummary{}, err
	}
	if err := db.Model(&WalletTransaction{}).Where("wallet_id = ? AND direction = ?", walletID, LedgerDirectionDebit).Select("COALESCE(SUM(amount), 0)").Scan(&debits).Error; err != nil {
		return WalletSummary{}, err
	}
	_ = db.Model(&Withdrawal{}).
		Where("wallet_id = ? AND status IN ?", walletID, []string{WithdrawalStatusRequested, WithdrawalStatusProcessing, WithdrawalStatusPending}).
		Select("COALESCE(SUM(amount), 0)").
		Scan(&pending).Error
	return WalletSummary{Currency: currency, Available: credits - debits, TotalCredits: credits, TotalDebits: debits, PendingWithdrawals: pending}, nil
}

func (s *Service) WalletTransactions(scope Scope, limit int) ([]WalletTransaction, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	wallet, err := s.walletForMerchant(s.db, scope.UserID, "UGX")
	if err != nil {
		return nil, err
	}
	var rows []WalletTransaction
	err = s.db.Where("wallet_id = ?", wallet.ID).Order("created_at desc").Limit(limit).Find(&rows).Error
	return rows, err
}

func (s *Service) LookupWithdrawalRecipient(scope Scope, destination string) (WithdrawalRecipient, error) {
	normalized := normalizeFinancePhone(destination)
	if normalized == "" {
		return WithdrawalRecipient{}, errors.New("payout destination is required")
	}

	name, status, err := s.latestVerifiedPayeeNameForPhone(s.db, scope, normalized)
	if err != nil {
		return WithdrawalRecipient{}, err
	}

	source := "iotec_unavailable_before_disbursement"
	if name != "" {
		source = "iotec_verified_history"
	}
	return WithdrawalRecipient{
		Destination: normalized,
		AccountName: name,
		Known:       name != "",
		Verified:    iotecPayeeNameVerified(status),
		Source:      source,
	}, nil
}

func (s *Service) RequestWithdrawal(scope Scope, amount int64, destination string) (Withdrawal, error) {
	return s.reserveMerchantWithdrawal(scope, amount, destination)
}

func (s *Service) RequestWithdrawalCode(scope Scope, user database.User, amount int64, destination string) (WithdrawalCodeDelivery, error) {
	email := strings.ToLower(strings.TrimSpace(user.Email))
	if user.ID != scope.UserID || email == "" {
		return WithdrawalCodeDelivery{}, errors.New("authenticated user email is required")
	}

	destination = strings.TrimSpace(destination)
	_, normalizedDestination, err := s.validateMerchantWithdrawal(s.db, scope, amount, destination)
	if err != nil {
		return WithdrawalCodeDelivery{}, err
	}
	destination = normalizedDestination

	payload, err := json.Marshal(withdrawalCodePayload{Amount: amount, Destination: destination})
	if err != nil {
		return WithdrawalCodeDelivery{}, err
	}

	code, err := newOneTimeCode()
	if err != nil {
		return WithdrawalCodeDelivery{}, err
	}

	now := time.Now()
	expiresAt := now.Add(withdrawalCodeTTL)
	if err := s.db.Model(&database.AuthCode{}).
		Where("email = ? AND purpose = ? AND used_at IS NULL", email, purposeWithdrawalCode).
		Update("used_at", now).Error; err != nil {
		return WithdrawalCodeDelivery{}, err
	}

	authCode := database.AuthCode{
		Email:     email,
		Purpose:   purposeWithdrawalCode,
		CodeHash:  hashCode(code),
		Payload:   string(payload),
		ExpiresAt: expiresAt,
	}
	if err := s.db.Create(&authCode).Error; err != nil {
		return WithdrawalCodeDelivery{}, err
	}

	delivery, err := sendWithdrawalCode(email, code)
	delivery.ExpiresAt = expiresAt
	return delivery, err
}

func (s *Service) ConfirmWithdrawal(scope Scope, user database.User, amount int64, destination, code string) (Withdrawal, error) {
	email := strings.ToLower(strings.TrimSpace(user.Email))
	if user.ID != scope.UserID || email == "" {
		return Withdrawal{}, errors.New("authenticated user email is required")
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return Withdrawal{}, errors.New("invalid or expired withdrawal code")
	}

	var out Withdrawal
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var authCode database.AuthCode
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("email = ? AND purpose = ? AND used_at IS NULL", email, purposeWithdrawalCode).
			Order("created_at desc").
			First(&authCode).Error
		if err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			return errors.New("invalid or expired withdrawal code")
		}
		if time.Now().After(authCode.ExpiresAt) || authCode.CodeHash != hashCode(code) {
			return errors.New("invalid or expired withdrawal code")
		}

		var payload withdrawalCodePayload
		if err := json.Unmarshal([]byte(authCode.Payload), &payload); err != nil {
			return errors.New("invalid or expired withdrawal code")
		}
		destination = normalizeFinancePhone(destination)
		if payload.Amount != amount || payload.Destination != destination {
			return errors.New("withdrawal details do not match the confirmation code")
		}

		now := time.Now()
		authCode.UsedAt = &now
		if err := tx.Save(&authCode).Error; err != nil {
			return err
		}

		withdrawal, err := s.createMerchantWithdrawal(tx, scope, amount, destination)
		if err != nil {
			return err
		}
		out = withdrawal
		return nil
	})
	if err != nil {
		return out, err
	}
	return s.initiateWithdrawalPayout(out.ID, user)
}

func (s *Service) reserveMerchantWithdrawal(scope Scope, amount int64, destination string) (Withdrawal, error) {
	var out Withdrawal
	err := s.db.Transaction(func(tx *gorm.DB) error {
		withdrawal, err := s.createMerchantWithdrawal(tx, scope, amount, destination)
		out = withdrawal
		return err
	})
	return out, err
}

func (s *Service) createMerchantWithdrawal(tx *gorm.DB, scope Scope, amount int64, destination string) (Withdrawal, error) {
	wallet, destination, err := s.validateMerchantWithdrawal(tx, scope, amount, destination)
	if err != nil {
		return Withdrawal{}, err
	}
	id := uuid.New()
	out := Withdrawal{
		ID:       id,
		WalletID: wallet.ID, OwnerUserID: wallet.OwnerUserID, WalletType: wallet.WalletType,
		Amount: amount, Currency: wallet.Currency, PayoutProvider: "iotec", PayoutDestination: destination,
		Status: WithdrawalStatusRequested, MerchantReference: merchantWithdrawalReference(id), RequestedByUserID: scope.UserID,
	}
	if err := tx.Create(&out).Error; err != nil {
		return Withdrawal{}, err
	}
	return out, s.createLedger(tx, wallet, wallet.OwnerUserID, LedgerTypeWithdrawalReserve, LedgerDirectionDebit, amount, wallet.Currency, "withdrawal", out.ID, "Withdrawal reserved for ioTec payout to "+destination, "withdrawal-reserve-"+out.ID.String())
}

func (s *Service) validateMerchantWithdrawal(db *gorm.DB, scope Scope, amount int64, destination string) (Wallet, string, error) {
	if amount <= 0 {
		return Wallet{}, "", errors.New("withdrawal amount must be greater than zero")
	}
	if s.cfg.MinimumWithdrawalUGX > 0 && amount < int64(s.cfg.MinimumWithdrawalUGX) {
		return Wallet{}, "", fmt.Errorf("minimum withdrawal is UGX %d", s.cfg.MinimumWithdrawalUGX)
	}
	destination = normalizeFinancePhone(destination)
	if destination == "" {
		return Wallet{}, "", errors.New("payout destination is required")
	}
	wallet, err := s.walletForMerchant(db, scope.UserID, "UGX")
	if err != nil {
		return Wallet{}, "", err
	}
	summary, err := s.walletSummaryFromDB(db, wallet.ID, "UGX")
	if err != nil {
		return Wallet{}, "", err
	}
	if summary.Available < amount {
		return Wallet{}, "", errors.New("insufficient available wallet balance")
	}
	return wallet, destination, nil
}

func (s *Service) latestCustomerNameForPhone(db *gorm.DB, scope Scope, phone string) (string, error) {
	phone = normalizeFinancePhone(phone)
	if phone == "" {
		return "", nil
	}

	query := db.Model(&Sale{}).
		Where("phone = ? AND customer_name <> '' AND customer_name <> ?", phone, phone).
		Order("sold_at desc")
	if !scope.IsSuperadmin {
		query = query.Where("owner_user_id = ?", scope.UserID)
	}

	var sale Sale
	if err := query.First(&sale).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}

	return strings.TrimSpace(sale.CustomerName), nil
}

func (s *Service) latestVerifiedPayeeNameForPhone(db *gorm.DB, scope Scope, phone string) (string, string, error) {
	phone = normalizeFinancePhone(phone)
	if phone == "" {
		return "", "", nil
	}

	query := db.Model(&Withdrawal{}).
		Where("payout_destination = ? AND payout_account_name <> ''", phone).
		Where("payee_name_status IN ?", []string{"Fetched", "Matched"}).
		Order("updated_at desc")
	if !scope.IsSuperadmin {
		query = query.Where("owner_user_id = ?", scope.UserID)
	}

	var withdrawal Withdrawal
	if err := query.First(&withdrawal).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", nil
		}
		return "", "", err
	}

	return strings.TrimSpace(withdrawal.PayoutAccountName), strings.TrimSpace(withdrawal.PayeeNameStatus), nil
}

func normalizeFinancePhone(value string) string {
	var digits strings.Builder
	for _, r := range strings.TrimSpace(value) {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	phone := digits.String()
	switch {
	case strings.HasPrefix(phone, "0") && len(phone) == 10:
		return "256" + phone[1:]
	case strings.HasPrefix(phone, "7") && len(phone) == 9:
		return "256" + phone
	default:
		return phone
	}
}

func merchantWithdrawalReference(id uuid.UUID) string {
	return "NOBLIFI-WD-" + strings.ToUpper(strings.ReplaceAll(id.String(), "-", ""))
}

func platformWithdrawalReference(id uuid.UUID) string {
	return "NOBLIFI-PF-WD-" + strings.ToUpper(strings.ReplaceAll(id.String(), "-", ""))
}

func iotecPayeeNameVerified(status string) bool {
	switch normalizeProviderStatus(status) {
	case "fetched", "matched":
		return true
	default:
		return false
	}
}

func normalizeProviderStatus(raw string) string {
	status := strings.ToLower(strings.TrimSpace(raw))
	status = strings.ReplaceAll(status, "_", "")
	status = strings.ReplaceAll(status, "-", "")
	status = strings.ReplaceAll(status, " ", "")
	return status
}

func (s *Service) initiateWithdrawalPayout(withdrawalID uuid.UUID, user database.User) (Withdrawal, error) {
	if s.payoutProvider == nil {
		if _, err := s.applyWithdrawalPayoutResult(withdrawalID, payments.PayoutResult{
			Status:        payments.PayoutStatusFailed,
			StatusMessage: "Payout provider is not configured.",
		}); err != nil {
			return Withdrawal{}, err
		}
		return Withdrawal{}, errors.New("payout provider is not configured")
	}

	var withdrawal Withdrawal
	if err := s.db.First(&withdrawal, "id = ?", withdrawalID).Error; err != nil {
		return Withdrawal{}, err
	}

	result, err := s.payoutProvider.InitiatePayout(payments.PayoutRequest{
		Reference: withdrawal.MerchantReference,
		Phone:     withdrawal.PayoutDestination,
		Amount:    withdrawal.Amount,
		Currency:  withdrawal.Currency,
		Email:     user.Email,
	})
	if err != nil {
		_, releaseErr := s.applyWithdrawalPayoutResult(withdrawalID, payments.PayoutResult{
			Status:        payments.PayoutStatusFailed,
			StatusMessage: err.Error(),
		})
		if releaseErr != nil {
			return Withdrawal{}, releaseErr
		}
		return Withdrawal{}, err
	}

	return s.applyWithdrawalPayoutResult(withdrawalID, result)
}

func (s *Service) RefreshWithdrawalStatus(scope Scope, withdrawalID uuid.UUID) (Withdrawal, error) {
	var withdrawal Withdrawal
	query := s.db.Where("id = ?", withdrawalID)
	if !scope.IsSuperadmin {
		query = query.Where("owner_user_id = ?", scope.UserID)
	}
	if err := query.First(&withdrawal).Error; err != nil {
		return Withdrawal{}, err
	}
	if withdrawal.Status == WithdrawalStatusPaid || withdrawal.Status == WithdrawalStatusFailed {
		return withdrawal, nil
	}
	if s.payoutProvider == nil {
		return Withdrawal{}, errors.New("payout provider is not configured")
	}
	if strings.TrimSpace(withdrawal.ProviderReference) == "" {
		return withdrawal, nil
	}

	result, err := s.payoutProvider.CheckPayoutStatus(withdrawal.ProviderReference)
	if err != nil {
		return Withdrawal{}, err
	}
	return s.applyWithdrawalPayoutResult(withdrawal.ID, result)
}

func (s *Service) applyWithdrawalPayoutResult(withdrawalID uuid.UUID, result payments.PayoutResult) (Withdrawal, error) {
	var out Withdrawal
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var withdrawal Withdrawal
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&withdrawal, "id = ?", withdrawalID).Error; err != nil {
			return err
		}

		if withdrawal.Status == WithdrawalStatusPaid || withdrawal.Status == WithdrawalStatusFailed {
			out = withdrawal
			return nil
		}

		now := time.Now()
		updates := map[string]any{
			"updated_at": now,
		}
		if result.Provider != "" {
			updates["payout_provider"] = result.Provider
			withdrawal.PayoutProvider = result.Provider
		}
		if result.MerchantReference != "" {
			updates["merchant_reference"] = result.MerchantReference
			withdrawal.MerchantReference = result.MerchantReference
		}
		if result.ProviderReference != "" {
			updates["provider_reference"] = result.ProviderReference
			withdrawal.ProviderReference = result.ProviderReference
		}
		if result.RawStatus != "" {
			updates["provider_status"] = result.RawStatus
			withdrawal.ProviderStatus = result.RawStatus
		}
		if result.StatusCode != "" {
			updates["provider_status_code"] = result.StatusCode
			withdrawal.ProviderStatusCode = result.StatusCode
		}
		if result.StatusMessage != "" {
			updates["provider_status_message"] = result.StatusMessage
			withdrawal.ProviderStatusMessage = result.StatusMessage
		}
		if result.Vendor != "" {
			updates["vendor"] = result.Vendor
			withdrawal.Vendor = result.Vendor
		}
		if result.VendorTransactionID != "" {
			updates["vendor_transaction_id"] = result.VendorTransactionID
			withdrawal.VendorTransactionID = result.VendorTransactionID
		}
		if result.Phone != "" {
			updates["payout_destination"] = normalizeFinancePhone(result.Phone)
			withdrawal.PayoutDestination = normalizeFinancePhone(result.Phone)
		}
		if result.PayeeName != "" {
			updates["payout_account_name"] = strings.TrimSpace(result.PayeeName)
			withdrawal.PayoutAccountName = strings.TrimSpace(result.PayeeName)
		}
		if result.PayeeNameStatus != "" {
			updates["payee_name_status"] = strings.TrimSpace(result.PayeeNameStatus)
			withdrawal.PayeeNameStatus = strings.TrimSpace(result.PayeeNameStatus)
		}

		switch result.Status {
		case payments.PayoutStatusPaid:
			updates["status"] = WithdrawalStatusPaid
			updates["processed_at"] = now
			updates["paid_at"] = now
			withdrawal.Status = WithdrawalStatusPaid
			withdrawal.ProcessedAt = &now
			withdrawal.PaidAt = &now
		case payments.PayoutStatusFailed:
			updates["status"] = WithdrawalStatusFailed
			updates["processed_at"] = now
			reason := strings.TrimSpace(firstNonEmpty(result.StatusMessage, result.RawStatus, "ioTec payout failed"))
			updates["failure_reason"] = reason
			withdrawal.Status = WithdrawalStatusFailed
			withdrawal.ProcessedAt = &now
			withdrawal.FailureReason = reason
		default:
			updates["status"] = WithdrawalStatusProcessing
			withdrawal.Status = WithdrawalStatusProcessing
		}

		if err := tx.Model(&Withdrawal{}).Where("id = ?", withdrawal.ID).Updates(updates).Error; err != nil {
			return err
		}

		if result.Status == payments.PayoutStatusFailed {
			wallet := Wallet{ID: withdrawal.WalletID, OwnerUserID: withdrawal.OwnerUserID, WalletType: withdrawal.WalletType, Currency: withdrawal.Currency}
			if err := s.createLedger(tx, wallet, withdrawal.OwnerUserID, LedgerTypeWithdrawalRelease, LedgerDirectionCredit, withdrawal.Amount, withdrawal.Currency, "withdrawal", withdrawal.ID, "Withdrawal reservation released after ioTec payout failure", "withdrawal-release-"+withdrawal.ID.String()); err != nil {
				return err
			}
		}

		out = withdrawal
		return nil
	})
	return out, err
}

func (s *Service) RequestPlatformWithdrawal(scope Scope, user database.User, amount int64, destination string) (Withdrawal, error) {
	if !scope.IsSuperadmin {
		return Withdrawal{}, errors.New("superadmin role required")
	}
	var out Withdrawal
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if amount <= 0 {
			return errors.New("withdrawal amount must be greater than zero")
		}
		wallet, err := s.platformWallet(tx, "UGX")
		if err != nil {
			return err
		}
		summary, err := s.walletSummary(wallet.ID, "UGX")
		if err != nil {
			return err
		}
		if summary.Available < amount {
			return errors.New("insufficient platform wallet balance")
		}
		id := uuid.New()
		out = Withdrawal{
			ID: id, WalletID: wallet.ID, OwnerUserID: nil, WalletType: wallet.WalletType,
			Amount: amount, Currency: wallet.Currency, PayoutProvider: "iotec", PayoutDestination: normalizeFinancePhone(destination),
			Status: WithdrawalStatusRequested, MerchantReference: platformWithdrawalReference(id), RequestedByUserID: scope.UserID,
		}
		if out.PayoutDestination == "" {
			return errors.New("payout destination is required")
		}
		if err := tx.Create(&out).Error; err != nil {
			return err
		}
		if err := s.createLedger(tx, wallet, nil, LedgerTypeWithdrawalReserve, LedgerDirectionDebit, amount, wallet.Currency, "withdrawal", out.ID, "Platform withdrawal reserved for ioTec payout to "+out.PayoutDestination, "platform-withdrawal-reserve-"+out.ID.String()); err != nil {
			return err
		}
		action := FinanceActionLog{ActorUserID: scope.UserID, Action: "platform_withdrawal_requested", TargetType: "withdrawal", TargetID: &out.ID, Amount: amount, Currency: wallet.Currency, Reason: "ioTec payout requested"}
		return tx.Create(&action).Error
	})
	if err != nil {
		return Withdrawal{}, err
	}
	return s.initiateWithdrawalPayout(out.ID, user)
}

func (s *Service) Withdrawals(scope Scope, limit int) ([]Withdrawal, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := s.db.Order("created_at desc").Limit(limit)
	if !scope.IsSuperadmin {
		query = query.Where("owner_user_id = ?", scope.UserID)
	}
	var rows []Withdrawal
	return rows, query.Find(&rows).Error
}

func (s *Service) Sales(scope Scope, limit int) ([]Sale, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := s.db.Order("sold_at desc").Limit(limit)
	if !scope.IsSuperadmin {
		query = query.Where("owner_user_id = ?", scope.UserID)
	}
	var rows []Sale
	return rows, query.Find(&rows).Error
}

func (s *Service) SalesSummary(scope Scope) (map[string]any, error) {
	query := s.db.Model(&Sale{})
	if !scope.IsSuperadmin {
		query = query.Where("owner_user_id = ?", scope.UserID)
	}
	var gross, fees, net, physical int64
	_ = query.Select("COALESCE(SUM(gross_amount), 0)").Scan(&gross).Error
	_ = query.Select("COALESCE(SUM(platform_fee_amount), 0)").Scan(&fees).Error
	_ = query.Select("COALESCE(SUM(merchant_net_amount), 0)").Scan(&net).Error
	_ = query.Where("source = ?", SaleSourcePhysical).Select("COALESCE(SUM(gross_amount), 0)").Scan(&physical).Error
	return map[string]any{"currency": "UGX", "gross_sales": gross, "platform_fees": fees, "merchant_net": net, "physical_sales": physical}, nil
}

func (s *Service) AdminFinanceSummary(scope Scope) (map[string]any, error) {
	if !scope.IsSuperadmin {
		return nil, errors.New("superadmin role required")
	}
	summary, err := s.SalesSummary(scope)
	if err != nil {
		return nil, err
	}
	platform, err := s.platformWallet(s.db, "UGX")
	if err != nil {
		return nil, err
	}
	platformSummary, _ := s.walletSummary(platform.ID, "UGX")
	summary["platform_wallet_available"] = platformSummary.Available
	return summary, nil
}

func (s *Service) walletForMerchant(db *gorm.DB, ownerID uuid.UUID, currency string) (Wallet, error) {
	var wallet Wallet
	err := db.Where("owner_user_id = ? AND wallet_type = ? AND currency = ?", ownerID, WalletTypeMerchant, currency).First(&wallet).Error
	if err == nil {
		return wallet, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return wallet, err
	}
	owner := ownerID
	wallet = Wallet{OwnerUserID: &owner, WalletType: WalletTypeMerchant, Currency: currency}
	return wallet, db.Create(&wallet).Error
}

func (s *Service) platformWallet(db *gorm.DB, currency string) (Wallet, error) {
	var wallet Wallet
	err := db.Where("owner_user_id IS NULL AND wallet_type = ? AND currency = ?", WalletTypePlatform, currency).First(&wallet).Error
	if err == nil {
		return wallet, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return wallet, err
	}
	wallet = Wallet{WalletType: WalletTypePlatform, Currency: currency}
	return wallet, db.Create(&wallet).Error
}

func (s *Service) createLedger(db *gorm.DB, wallet Wallet, ownerID *uuid.UUID, typ, direction string, amount int64, currency, refType string, refID uuid.UUID, description, key string) error {
	if amount <= 0 {
		return errors.New("ledger amount must be greater than zero")
	}
	ref := refID
	row := WalletTransaction{
		WalletID: wallet.ID, OwnerUserID: ownerID, Type: typ, Direction: direction, Amount: amount,
		Currency: currency, ReferenceType: refType, ReferenceID: &ref, Description: description, IdempotencyKey: key,
	}
	if err := db.Create(&row).Error; err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		return err
	}
	return nil
}

func newOneTimeCode() (string, error) {
	var bytes [6]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	for i, value := range bytes {
		bytes[i] = '0' + (value % 10)
	}
	return string(bytes[:]), nil
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func sendWithdrawalCode(email, code string) (WithdrawalCodeDelivery, error) {
	subject := "Your NobliFi withdrawal confirmation code"
	action := "confirm your wallet withdrawal"

	if resendKey := strings.TrimSpace(os.Getenv("RESEND_API_KEY")); resendKey != "" {
		fromEmail := strings.TrimSpace(os.Getenv("RESEND_FROM_EMAIL"))
		if fromEmail == "" {
			fromEmail = "no-reply@noblifi.local"
		}
		fromName := strings.TrimSpace(os.Getenv("RESEND_FROM_NAME"))
		fromHeader := fromEmail
		if fromName != "" {
			fromHeader = fromName + " <" + fromEmail + ">"
		}

		bodyText := "Use this one-time password code to " + action + ": " + code + "\n\nThis code expires in 15 minutes."
		payload := map[string]any{
			"from":    fromHeader,
			"to":      []string{email},
			"subject": subject,
			"text":    bodyText,
		}
		jsonBody, err := json.Marshal(payload)
		if err != nil {
			return WithdrawalCodeDelivery{Sent: false, Message: "Could not prepare email payload."}, err
		}

		req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(jsonBody))
		if err != nil {
			return WithdrawalCodeDelivery{Sent: false, Message: "Could not build email request."}, err
		}
		req.Header.Set("Authorization", "Bearer "+resendKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
		if err != nil {
			return WithdrawalCodeDelivery{Sent: false, Message: "Could not send email via Resend."}, err
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			var errBody any
			_ = json.NewDecoder(resp.Body).Decode(&errBody)
			return WithdrawalCodeDelivery{Sent: false, Message: "Could not send email via Resend."}, errors.New("resend email failed")
		}

		return WithdrawalCodeDelivery{Sent: true, SMTPEnabled: false, Message: "Withdrawal confirmation code sent by email."}, nil
	}

	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	port := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))
	username := strings.TrimSpace(os.Getenv("SMTP_USERNAME"))
	password := os.Getenv("SMTP_PASSWORD")
	if port == "" {
		port = "587"
	}

	if host == "" || from == "" {
		log.Printf("one-time %s code for %s: %s", purposeWithdrawalCode, email, code)
		return WithdrawalCodeDelivery{
			Sent:        false,
			DevCode:     code,
			Message:     "Email is not configured; use the displayed development code.",
			SMTPEnabled: false,
		}, nil
	}

	body := "Use this one-time password code to " + action + ": " + code + "\r\n\r\nThis code expires in 15 minutes."
	message := []byte("To: " + email + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		body + "\r\n")

	var auth smtp.Auth
	if username != "" || password != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	if err := smtp.SendMail(host+":"+port, auth, from, []string{email}, message); err != nil {
		return WithdrawalCodeDelivery{Sent: false, SMTPEnabled: true, Message: "Could not send email through SMTP."}, err
	}
	return WithdrawalCodeDelivery{Sent: true, SMTPEnabled: true, Message: "Withdrawal confirmation code sent by email."}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func randomHex(byteCount int) string {
	bytes := uuid.New()
	return strings.ReplaceAll(bytes.String(), "-", "")[:byteCount*2]
}

var _ = routers.Router{}
