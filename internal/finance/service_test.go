package finance

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/database"
	"github.com/noblifi/noblifi/backend/internal/payments"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestCalculateCommissionMobileMoney(t *testing.T) {
	fee, net, err := CalculateCommission(SaleSourceMobileMoney, 10000, 500)
	if err != nil {
		t.Fatalf("CalculateCommission returned error: %v", err)
	}
	if fee != 500 || net != 9500 {
		t.Fatalf("fee/net = %d/%d, want 500/9500", fee, net)
	}
}

func TestCalculateCommissionPhysicalHasNoPlatformFee(t *testing.T) {
	fee, net, err := CalculateCommission(SaleSourcePhysical, 10000, 500)
	if err != nil {
		t.Fatalf("CalculateCommission returned error: %v", err)
	}
	if fee != 0 || net != 10000 {
		t.Fatalf("fee/net = %d/%d, want 0/10000", fee, net)
	}
}

func TestCalculateCommissionRejectsInvalidGross(t *testing.T) {
	if _, _, err := CalculateCommission(SaleSourceMobileMoney, 0, 500); err == nil {
		t.Fatal("expected invalid gross amount to fail")
	}
}

func TestNormalizeFinancePhone(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0757251514", "256757251514"},
		{"757251514", "256757251514"},
		{"+256757251514", "256757251514"},
		{"256757251514", "256757251514"},
	}

	for _, test := range tests {
		if got := normalizeFinancePhone(test.input); got != test.want {
			t.Fatalf("%q: got %q want %q", test.input, got, test.want)
		}
	}
}

func TestIotecPayeeNameVerified(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"Fetched", true},
		{"Matched", true},
		{"Pending", false},
		{"NotMatched", false},
		{"NotFound", false},
		{"Failed", false},
		{"Barred", false},
	}

	for _, test := range tests {
		if got := iotecPayeeNameVerified(test.input); got != test.want {
			t.Fatalf("%q: got %v want %v", test.input, got, test.want)
		}
	}
}

func TestMerchantWithdrawalPendingThenSuccessIsIdempotent(t *testing.T) {
	db := testFinanceDB(t)
	user := testUser(t, db)
	service := NewService(db, config.Config{}, nil)
	provider := &mockPayoutProvider{
		initiateResult: payments.PayoutResult{
			Provider:          "iotec",
			ProviderReference: "provider-1",
			MerchantReference: "merchant-1",
			Status:            payments.PayoutStatusProcessing,
			RawStatus:         "Pending",
		},
		checkResults: []payments.PayoutResult{{
			Provider:            "iotec",
			ProviderReference:   "provider-1",
			MerchantReference:   "merchant-1",
			Status:              payments.PayoutStatusPaid,
			RawStatus:           "Success",
			PayeeName:           "JOHN DOE",
			PayeeNameStatus:     "Fetched",
			Vendor:              "mtn",
			VendorTransactionID: "vendor-1",
		}},
	}
	service.SetPayoutProvider(provider)
	creditWallet(t, service, user.ID, 100000)

	withdrawal := reserveAndInitiate(t, service, user, 40000)
	if withdrawal.Status != WithdrawalStatusProcessing {
		t.Fatalf("status = %q, want processing", withdrawal.Status)
	}
	assertSummary(t, service, user.ID, 60000, 40000)
	assertLedgerCount(t, db, LedgerDirectionDebit, 1)

	refreshed, err := service.RefreshWithdrawalStatus(Scope{UserID: user.ID}, withdrawal.ID)
	if err != nil {
		t.Fatalf("RefreshWithdrawalStatus: %v", err)
	}
	if refreshed.Status != WithdrawalStatusPaid {
		t.Fatalf("status = %q, want paid", refreshed.Status)
	}
	if refreshed.PayoutAccountName != "JOHN DOE" || refreshed.PayeeNameStatus != "Fetched" {
		t.Fatalf("payee = %q/%q, want JOHN DOE/Fetched", refreshed.PayoutAccountName, refreshed.PayeeNameStatus)
	}
	assertSummary(t, service, user.ID, 60000, 0)
	assertLedgerCount(t, db, LedgerDirectionDebit, 1)

	again, err := service.RefreshWithdrawalStatus(Scope{UserID: user.ID}, withdrawal.ID)
	if err != nil {
		t.Fatalf("second RefreshWithdrawalStatus: %v", err)
	}
	if again.Status != WithdrawalStatusPaid {
		t.Fatalf("second status = %q, want paid", again.Status)
	}
	assertLedgerCount(t, db, LedgerDirectionDebit, 1)
	if provider.checkCalls != 1 {
		t.Fatalf("provider check calls = %d, want 1", provider.checkCalls)
	}
}

func TestMerchantWithdrawalFailureReleasesReservationOnce(t *testing.T) {
	db := testFinanceDB(t)
	user := testUser(t, db)
	service := NewService(db, config.Config{}, nil)
	provider := &mockPayoutProvider{
		initiateResult: payments.PayoutResult{
			Provider:          "iotec",
			ProviderReference: "provider-2",
			MerchantReference: "merchant-2",
			Status:            payments.PayoutStatusProcessing,
			RawStatus:         "SentToVendor",
			PayeeName:         "JOHN DOE",
			PayeeNameStatus:   "Fetched",
		},
		checkResults: []payments.PayoutResult{{
			Provider:          "iotec",
			ProviderReference: "provider-2",
			MerchantReference: "merchant-2",
			Status:            payments.PayoutStatusFailed,
			RawStatus:         "Failed",
			StatusMessage:     "Insufficient vendor balance",
		}},
	}
	service.SetPayoutProvider(provider)
	creditWallet(t, service, user.ID, 100000)

	withdrawal := reserveAndInitiate(t, service, user, 40000)
	if withdrawal.Status != WithdrawalStatusProcessing {
		t.Fatalf("status = %q, want processing", withdrawal.Status)
	}
	if withdrawal.PayoutAccountName != "JOHN DOE" || withdrawal.PayeeNameStatus != "Fetched" {
		t.Fatalf("payee = %q/%q, want JOHN DOE/Fetched", withdrawal.PayoutAccountName, withdrawal.PayeeNameStatus)
	}
	assertSummary(t, service, user.ID, 60000, 40000)

	refreshed, err := service.RefreshWithdrawalStatus(Scope{UserID: user.ID}, withdrawal.ID)
	if err != nil {
		t.Fatalf("RefreshWithdrawalStatus: %v", err)
	}
	if refreshed.Status != WithdrawalStatusFailed {
		t.Fatalf("status = %q, want failed", refreshed.Status)
	}
	assertSummary(t, service, user.ID, 100000, 0)
	assertLedgerTypeCount(t, db, LedgerTypeWithdrawalRelease, 1)

	if _, err := service.RefreshWithdrawalStatus(Scope{UserID: user.ID}, withdrawal.ID); err != nil {
		t.Fatalf("second RefreshWithdrawalStatus: %v", err)
	}
	assertSummary(t, service, user.ID, 100000, 0)
	assertLedgerTypeCount(t, db, LedgerTypeWithdrawalRelease, 1)
}

func TestMerchantWithdrawalDoesNotTreatInitialPendingAsPaid(t *testing.T) {
	db := testFinanceDB(t)
	user := testUser(t, db)
	service := NewService(db, config.Config{}, nil)
	service.SetPayoutProvider(&mockPayoutProvider{
		initiateResult: payments.PayoutResult{
			Provider:          "iotec",
			ProviderReference: "provider-3",
			Status:            payments.PayoutStatusProcessing,
			RawStatus:         "Pending",
		},
	})
	creditWallet(t, service, user.ID, 100000)

	withdrawal := reserveAndInitiate(t, service, user, 40000)
	if withdrawal.Status == WithdrawalStatusPaid {
		t.Fatal("initial Pending payout was marked paid")
	}
	assertSummary(t, service, user.ID, 60000, 40000)
}

func TestWithdrawalStatusIsTenantScoped(t *testing.T) {
	db := testFinanceDB(t)
	tenantA := testUser(t, db)
	tenantB := testUser(t, db)
	service := NewService(db, config.Config{}, nil)
	provider := &mockPayoutProvider{
		initiateResult: payments.PayoutResult{
			ProviderReference: "provider-4",
			Status:            payments.PayoutStatusProcessing,
			RawStatus:         "Pending",
		},
	}
	service.SetPayoutProvider(provider)
	creditWallet(t, service, tenantB.ID, 100000)

	withdrawal := reserveAndInitiate(t, service, tenantB, 40000)
	if _, err := service.RefreshWithdrawalStatus(Scope{UserID: tenantA.ID}, withdrawal.ID); err == nil {
		t.Fatal("expected cross-tenant withdrawal status refresh to fail")
	}
	if provider.checkCalls != 0 {
		t.Fatalf("provider check calls = %d, want 0", provider.checkCalls)
	}
}

func TestPlatformWithdrawalUsesIotecPayout(t *testing.T) {
	db := testFinanceDB(t)
	admin := database.User{ID: uuid.New(), Email: uuid.NewString() + "@example.com", Role: "superadmin", Name: "NobliFi Admin"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}
	service := NewService(db, config.Config{}, nil)
	provider := &mockPayoutProvider{
		initiateResult: payments.PayoutResult{
			Provider:          "iotec",
			ProviderReference: "platform-provider-1",
			Status:            payments.PayoutStatusProcessing,
			RawStatus:         "Pending",
			PayeeName:         "NOBLIFI ADMIN",
			PayeeNameStatus:   "Fetched",
		},
	}
	service.SetPayoutProvider(provider)
	creditPlatformWallet(t, service, 100000)

	withdrawal, err := service.RequestPlatformWithdrawal(Scope{UserID: admin.ID, IsSuperadmin: true}, admin, 25000, "0757251514")
	if err != nil {
		t.Fatalf("RequestPlatformWithdrawal: %v", err)
	}
	if withdrawal.Status != WithdrawalStatusProcessing {
		t.Fatalf("status = %q, want processing", withdrawal.Status)
	}
	if withdrawal.PayoutProvider != "iotec" {
		t.Fatalf("provider = %q, want iotec", withdrawal.PayoutProvider)
	}
	if withdrawal.OwnerUserID != nil {
		t.Fatalf("OwnerUserID = %v, want nil for platform wallet", withdrawal.OwnerUserID)
	}
	if !strings.HasPrefix(withdrawal.MerchantReference, "NOBLIFI-PF-WD-") {
		t.Fatalf("merchant reference = %q, want platform withdrawal prefix", withdrawal.MerchantReference)
	}
	if provider.initiateCalls != 1 {
		t.Fatalf("provider initiate calls = %d, want 1", provider.initiateCalls)
	}
	if provider.lastInitiate.Phone != "256757251514" {
		t.Fatalf("provider phone = %q, want normalized phone", provider.lastInitiate.Phone)
	}
	summary, err := service.walletSummary(withdrawal.WalletID, "UGX")
	if err != nil {
		t.Fatalf("walletSummary: %v", err)
	}
	if summary.Available != 75000 || summary.PendingWithdrawals != 25000 {
		t.Fatalf("summary available/pending = %d/%d, want 75000/25000", summary.Available, summary.PendingWithdrawals)
	}
}

type mockPayoutProvider struct {
	initiateResult payments.PayoutResult
	checkResults   []payments.PayoutResult
	initiateCalls  int
	lastInitiate   payments.PayoutRequest
	checkCalls     int
}

func (m *mockPayoutProvider) InitiatePayout(input payments.PayoutRequest) (payments.PayoutResult, error) {
	m.initiateCalls++
	m.lastInitiate = input
	result := m.initiateResult
	if result.MerchantReference == "" {
		result.MerchantReference = input.Reference
	}
	return result, nil
}

func (m *mockPayoutProvider) CheckPayoutStatus(transactionID string) (payments.PayoutResult, error) {
	m.checkCalls++
	if len(m.checkResults) == 0 {
		return payments.PayoutResult{ProviderReference: transactionID, Status: payments.PayoutStatusProcessing, RawStatus: "Pending"}, nil
	}
	return m.checkResults[0], nil
}

func testFinanceDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&database.User{}, &Sale{}, &Wallet{}, &WalletTransaction{}, &Withdrawal{}, &FinanceActionLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testUser(t *testing.T, db *gorm.DB) database.User {
	t.Helper()
	user := database.User{ID: uuid.New(), Email: uuid.NewString() + "@example.com", Role: "merchant"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func creditWallet(t *testing.T, service *Service, userID uuid.UUID, amount int64) {
	t.Helper()
	wallet, err := service.walletForMerchant(service.db, userID, "UGX")
	if err != nil {
		t.Fatalf("walletForMerchant: %v", err)
	}
	if err := service.createLedger(service.db, wallet, &userID, LedgerTypeSaleCredit, LedgerDirectionCredit, amount, "UGX", "test", uuid.New(), "test credit", "test-credit-"+uuid.NewString()); err != nil {
		t.Fatalf("createLedger: %v", err)
	}
}

func creditPlatformWallet(t *testing.T, service *Service, amount int64) {
	t.Helper()
	wallet, err := service.platformWallet(service.db, "UGX")
	if err != nil {
		t.Fatalf("platformWallet: %v", err)
	}
	if err := service.createLedger(service.db, wallet, nil, LedgerTypePlatformCommission, LedgerDirectionCredit, amount, "UGX", "test", uuid.New(), "test platform credit", "test-platform-credit-"+uuid.NewString()); err != nil {
		t.Fatalf("createLedger: %v", err)
	}
}

func reserveAndInitiate(t *testing.T, service *Service, user database.User, amount int64) Withdrawal {
	t.Helper()
	var withdrawal Withdrawal
	err := service.db.Transaction(func(tx *gorm.DB) error {
		var err error
		withdrawal, err = service.createMerchantWithdrawal(tx, Scope{UserID: user.ID}, amount, "0757251514")
		return err
	})
	if err != nil {
		t.Fatalf("createMerchantWithdrawal: %v", err)
	}
	withdrawal, err = service.initiateWithdrawalPayout(withdrawal.ID, user)
	if err != nil {
		t.Fatalf("initiateWithdrawalPayout: %v", err)
	}
	return withdrawal
}

func assertSummary(t *testing.T, service *Service, userID uuid.UUID, available, pending int64) {
	t.Helper()
	summary, err := service.WalletSummary(Scope{UserID: userID})
	if err != nil {
		t.Fatalf("WalletSummary: %v", err)
	}
	if summary.Available != available || summary.PendingWithdrawals != pending {
		t.Fatalf("summary available/pending = %d/%d, want %d/%d", summary.Available, summary.PendingWithdrawals, available, pending)
	}
}

func assertLedgerCount(t *testing.T, db *gorm.DB, direction string, want int64) {
	t.Helper()
	var count int64
	if err := db.Model(&WalletTransaction{}).Where("direction = ?", direction).Count(&count).Error; err != nil {
		t.Fatalf("count ledger: %v", err)
	}
	if count != want {
		t.Fatalf("%s ledger count = %d, want %d", direction, count, want)
	}
}

func assertLedgerTypeCount(t *testing.T, db *gorm.DB, typ string, want int64) {
	t.Helper()
	var count int64
	if err := db.Model(&WalletTransaction{}).Where("type = ?", typ).Count(&count).Error; err != nil {
		t.Fatalf("count ledger type: %v", err)
	}
	if count != want {
		t.Fatalf("%s ledger count = %d, want %d", typ, count, want)
	}
}
