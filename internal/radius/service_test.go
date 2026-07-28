package radius

import (
	"testing"
	"time"
)

func TestVoucherUsageStateMarksUnusedAsUsed(t *testing.T) {
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)

	status, usedAt := voucherUsageState("unused", nil, now)
	if status != "used" {
		t.Fatalf("expected status to be used, got %q", status)
	}
	if usedAt == nil || !usedAt.Equal(now) {
		t.Fatalf("expected used_at to be set to %v, got %v", now, usedAt)
	}
}

func TestVoucherUsageStatePreservesExistingUsedState(t *testing.T) {
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	previous := time.Date(2026, 7, 27, 9, 30, 0, 0, time.UTC)

	status, usedAt := voucherUsageState("used", &previous, now)
	if status != "used" {
		t.Fatalf("expected status to remain used, got %q", status)
	}
	if usedAt == nil || !usedAt.Equal(previous) {
		t.Fatalf("expected used_at to remain %v, got %v", previous, usedAt)
	}
}
