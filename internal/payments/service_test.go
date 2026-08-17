package payments

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/database"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestApplyStatusActivatesUserSubscription(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&database.User{}, &plans.Plan{}, &vouchers.Voucher{}, &PaymentOrder{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	plan := plans.Plan{
		ID:              uuid.New(),
		Name:            "Pro Plan",
		Price:           45000,
		DurationMinutes: 43200,
		IsActive:        true,
	}
	if err := db.Create(&plan).Error; err != nil {
		t.Fatalf("create plan: %v", err)
	}

	trialEndsAt := time.Now().Add(24 * time.Hour)
	user := database.User{
		Email:           "subscriber@example.com",
		Name:            "Subscriber",
		Role:            "admin",
		HotspotName:     "Demo WiFi",
		BillingPlan:     "Free Trial",
		MonthlyPriceUGX: 0,
		TrialEndsAt:     &trialEndsAt,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	svc := &Service{db: db, cfg: config.Config{IotecCurrency: "UGX"}}
	order := PaymentOrder{
		ID:                uuid.New(),
		MerchantReference: "NOBLIFI-TEST",
		OrderTrackingID:   "abc-123",
		PlanID:            plan.ID,
		Amount:            plan.Price,
		Currency:          "UGX",
		Email:             user.Email,
	}

	if _, err := svc.applyStatus(order, iotecStatusResponse{RawStatus: "paid", raw: map[string]any{"status": "paid"}}); err != nil {
		t.Fatalf("apply status: %v", err)
	}

	var updated database.User
	if err := db.Where("email = ?", user.Email).First(&updated).Error; err != nil {
		t.Fatalf("find updated user: %v", err)
	}
	if updated.BillingPlan != plan.Name {
		t.Fatalf("billing plan mismatch: got %q want %q", updated.BillingPlan, plan.Name)
	}
	if updated.MonthlyPriceUGX != plan.Price {
		t.Fatalf("monthly price mismatch: got %d want %d", updated.MonthlyPriceUGX, plan.Price)
	}
	if updated.TrialEndsAt != nil {
		t.Fatalf("expected trial to be cleared, got non-nil value %v", *updated.TrialEndsAt)
	}
}
