//go:build cgo

package revenue

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/database"
	"github.com/noblifi/noblifi/backend/internal/payments"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSummaryOnlyCountsPaidHotspotPurchases(t *testing.T) {
	db := testDB(t)
	userID := uuid.New()
	routerID := uuid.New()
	planID := uuid.New()
	createPurchase(t, db, userID, routerID, planID, "pending", 5000)
	createPurchase(t, db, userID, routerID, planID, "failed", 5000)
	createPurchase(t, db, userID, routerID, planID, "paid", 5000)

	summary, err := NewService(db).Summary(Scope{UserID: userID}, Filters{})
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.TotalRevenue != 5000 {
		t.Fatalf("TotalRevenue = %d, want 5000", summary.TotalRevenue)
	}
	if summary.SuccessfulPayments != 1 || summary.PendingPayments != 1 || summary.FailedPayments != 1 {
		t.Fatalf("status counts mismatch: successful=%d pending=%d failed=%d", summary.SuccessfulPayments, summary.PendingPayments, summary.FailedPayments)
	}
}

func TestSummaryGrossRevenueExcludesPendingValue(t *testing.T) {
	db := testDB(t)
	userID := uuid.New()
	routerID := uuid.New()
	planID := uuid.New()
	createPurchase(t, db, userID, routerID, planID, "paid", 2000)
	createPurchase(t, db, userID, routerID, planID, "paid", 5000)
	createPurchase(t, db, userID, routerID, planID, "pending", 10000)

	summary, err := NewService(db).Summary(Scope{UserID: userID}, Filters{})
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.TotalRevenue != 7000 {
		t.Fatalf("TotalRevenue = %d, want 7000", summary.TotalRevenue)
	}
	if summary.SuccessfulPayments != 2 || summary.PendingPayments != 1 {
		t.Fatalf("counts mismatch: successful=%d pending=%d", summary.SuccessfulPayments, summary.PendingPayments)
	}
}

func TestRevenueUsesHistoricalPurchaseAmount(t *testing.T) {
	db := testDB(t)
	userID := uuid.New()
	routerID := uuid.New()
	planID := uuid.New()
	plan := plans.Plan{ID: planID, UserID: &userID, Name: "1 Hour", Price: 2000, DurationMinutes: 60, MaxDevices: 1, IsActive: true}
	if err := db.Create(&plan).Error; err != nil {
		t.Fatalf("create plan: %v", err)
	}
	createPurchase(t, db, userID, routerID, planID, "paid", 2000)
	if err := db.Model(&plans.Plan{}).Where("id = ?", planID).Update("price", 3000).Error; err != nil {
		t.Fatalf("update plan: %v", err)
	}
	summary, err := NewService(db).Summary(Scope{UserID: userID}, Filters{})
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.TotalRevenue != 2000 {
		t.Fatalf("TotalRevenue = %d, want historical amount 2000", summary.TotalRevenue)
	}
}

func TestRevenueIsTenantScoped(t *testing.T) {
	db := testDB(t)
	tenantA := uuid.New()
	tenantB := uuid.New()
	routerID := uuid.New()
	planID := uuid.New()
	createPurchase(t, db, tenantA, routerID, planID, "paid", 20000)
	createPurchase(t, db, tenantB, routerID, planID, "paid", 50000)

	summary, err := NewService(db).Summary(Scope{UserID: tenantA}, Filters{})
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.TotalRevenue != 20000 {
		t.Fatalf("TotalRevenue = %d, want tenant A only 20000", summary.TotalRevenue)
	}
}

func TestRevenueRouterFilter(t *testing.T) {
	db := testDB(t)
	userID := uuid.New()
	routerA := uuid.New()
	routerB := uuid.New()
	planID := uuid.New()
	createPurchase(t, db, userID, routerA, planID, "paid", 15000)
	createPurchase(t, db, userID, routerB, planID, "paid", 25000)

	service := NewService(db)
	all, err := service.Summary(Scope{UserID: userID}, Filters{})
	if err != nil {
		t.Fatalf("summary all: %v", err)
	}
	a, err := service.Summary(Scope{UserID: userID}, Filters{RouterID: routerA.String()})
	if err != nil {
		t.Fatalf("summary router A: %v", err)
	}
	b, err := service.Summary(Scope{UserID: userID}, Filters{RouterID: routerB.String()})
	if err != nil {
		t.Fatalf("summary router B: %v", err)
	}
	if all.TotalRevenue != 40000 || a.TotalRevenue != 15000 || b.TotalRevenue != 25000 {
		t.Fatalf("router filter mismatch: all=%d a=%d b=%d", all.TotalRevenue, a.TotalRevenue, b.TotalRevenue)
	}
}

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&database.User{}, &routers.Router{}, &plans.Plan{}, &vouchers.Voucher{}, &payments.HotspotPurchase{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func createPurchase(t *testing.T, db *gorm.DB, ownerID uuid.UUID, routerID uuid.UUID, planID uuid.UUID, status string, amount int) {
	t.Helper()
	now := time.Now()
	purchase := payments.HotspotPurchase{
		ID: uuid.New(), OwnerUserID: ownerID, RouterID: routerID, PlanID: planID,
		DeviceMAC: "AA:BB:CC:DD:EE:FF", MerchantReference: uuid.NewString(),
		Provider: "iotec", Status: status, Amount: amount, Currency: "UGX",
	}
	if status == "paid" {
		purchase.PaidAt = &now
	}
	if err := db.Create(&purchase).Error; err != nil {
		t.Fatalf("create purchase: %v", err)
	}
}
