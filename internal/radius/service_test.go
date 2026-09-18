package radius

import (
	"bytes"
	"crypto/md5"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/vouchers"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestVoucherUsageStateMarksUnusedAsActive(t *testing.T) {
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)

	status, usedAt := voucherUsageState("unused", nil, now)
	if status != "active" {
		t.Fatalf("expected status to be active, got %q", status)
	}
	if usedAt == nil || !usedAt.Equal(now) {
		t.Fatalf("expected used_at to be set to %v, got %v", now, usedAt)
	}
}

func TestVoucherUsageStatePreservesExistingActiveState(t *testing.T) {
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	previous := time.Date(2026, 7, 27, 9, 30, 0, 0, time.UTC)

	status, usedAt := voucherUsageState("active", &previous, now)
	if status != "active" {
		t.Fatalf("expected status to remain active, got %q", status)
	}
	if usedAt == nil || !usedAt.Equal(previous) {
		t.Fatalf("expected used_at to remain %v, got %v", previous, usedAt)
	}
}

func TestRemainingVoucherSecondsUsesWallClockExpiry(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(2*time.Hour + 15*time.Minute)

	remaining := remainingVoucherSeconds(
		testVoucherWithExpiry(expiresAt),
		testPlanWithDuration(3*60),
		now,
	)
	if remaining != 8100 {
		t.Fatalf("remaining seconds = %d, want 8100", remaining)
	}
}

func TestRemainingVoucherSecondsRejectsExpiredVoucher(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	expiresAt := now.Add(-time.Second)

	remaining := remainingVoucherSeconds(
		testVoucherWithExpiry(expiresAt),
		testPlanWithDuration(3*60),
		now,
	)
	if remaining != 0 {
		t.Fatalf("remaining seconds = %d, want 0", remaining)
	}
}

func TestHandleAccessPacketBindsVoucherToCallingStationID(t *testing.T) {
	db := testRadiusDB(t)
	service := NewService(db)
	plan := plans.Plan{
		ID:              uuid.New(),
		Name:            "One Hour",
		DurationMinutes: 60,
		IsActive:        true,
	}
	if err := db.Create(&plan).Error; err != nil {
		t.Fatalf("create plan: %v", err)
	}
	voucher := vouchers.Voucher{
		ID:     uuid.New(),
		Code:   "NF-TEST1",
		PlanID: plan.ID,
		Status: "unused",
	}
	if err := db.Create(&voucher).Error; err != nil {
		t.Fatalf("create voucher: %v", err)
	}

	first := testAccessRequest("NF-TEST1", "AA-BB-CC-DD-EE-FF", "radius-secret")
	response, err := service.handleAccessPacket(first, testRemoteAddr(), "radius-secret")
	if err != nil {
		t.Fatalf("first access packet: %v", err)
	}
	if response[0] != radiusAccessAccept {
		t.Fatalf("first response code = %d, want Access-Accept", response[0])
	}

	var bound vouchers.Voucher
	if err := db.First(&bound, "code = ?", "NF-TEST1").Error; err != nil {
		t.Fatalf("load bound voucher: %v", err)
	}
	if bound.DeviceMAC == nil || *bound.DeviceMAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("device_mac = %v, want AA:BB:CC:DD:EE:FF", bound.DeviceMAC)
	}

	second := testAccessRequest("NF-TEST1", "11:22:33:44:55:66", "radius-secret")
	response, err = service.handleAccessPacket(second, testRemoteAddr(), "radius-secret")
	if err != nil {
		t.Fatalf("second access packet: %v", err)
	}
	if response[0] != radiusAccessReject {
		t.Fatalf("second response code = %d, want Access-Reject", response[0])
	}
}

func TestBindVoucherToDeviceForUserAllowsOwnerAndRejectsOtherAccount(t *testing.T) {
	db := testRadiusDB(t)
	service := NewService(db)
	ownerID := uuid.New()
	otherID := uuid.New()
	plan := plans.Plan{ID: uuid.New(), Name: "Account package", DurationMinutes: 60, IsActive: true}
	if err := db.Create(&plan).Error; err != nil {
		t.Fatalf("create plan: %v", err)
	}
	voucher := vouchers.Voucher{ID: uuid.New(), UserID: &ownerID, Code: "NF-OWNER1", PlanID: plan.ID, Status: "unused"}
	if err := db.Create(&voucher).Error; err != nil {
		t.Fatalf("create voucher: %v", err)
	}

	if _, err := service.BindVoucherToDeviceForUser(voucher.Code, "AA:BB:CC:DD:EE:FF", otherID.String()); !errors.Is(err, ErrVoucherUnavailable) {
		t.Fatalf("other account error = %v, want ErrVoucherUnavailable", err)
	}
	if _, err := service.BindVoucherToDeviceForUser(voucher.Code, "AA:BB:CC:DD:EE:FF", ownerID.String()); err != nil {
		t.Fatalf("owner should be able to bind voucher: %v", err)
	}
}

func testVoucherWithExpiry(expiresAt time.Time) vouchers.Voucher {
	return vouchers.Voucher{ExpiresAt: &expiresAt}
}

func testPlanWithDuration(minutes int) plans.Plan {
	return plans.Plan{DurationMinutes: minutes}
}

func testRadiusDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		if strings.Contains(err.Error(), "requires cgo") {
			t.Skipf("sqlite driver unavailable: %v", err)
		}
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&plans.Plan{},
		&vouchers.Voucher{},
		&RadCheck{},
		&RadReply{},
		&RadAcct{},
	); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	return db
}

func testAccessRequest(username, callingStationID, secret string) radiusPacket {
	authenticator := []byte("1234567890abcdef")
	return radiusPacket{
		Code:          radiusAccessRequest,
		Identifier:    7,
		Authenticator: authenticator,
		Attributes: map[byte][][]byte{
			attrUserName:         {[]byte(username)},
			attrUserPassword:     {encryptUserPassword(username, secret, authenticator)},
			attrCallingStationID: {[]byte(callingStationID)},
		},
	}
}

func testRemoteAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1812}
}

func encryptUserPassword(password, secret string, authenticator []byte) []byte {
	plain := append([]byte(password), 0)
	for len(plain)%16 != 0 {
		plain = append(plain, 0)
	}

	encrypted := make([]byte, 0, len(plain))
	previous := authenticator
	for offset := 0; offset < len(plain); offset += 16 {
		sum := md5.Sum(append([]byte(secret), previous...))
		block := make([]byte, 16)
		for i := range block {
			block[i] = plain[offset+i] ^ sum[i]
		}
		encrypted = append(encrypted, block...)
		previous = block
	}
	return encrypted
}

func TestEncryptUserPasswordHelperMatchesDecrypt(t *testing.T) {
	authenticator := []byte("1234567890abcdef")
	encrypted := encryptUserPassword("NF-TEST1", "radius-secret", authenticator)
	if got := decryptUserPassword(encrypted, "radius-secret", authenticator); !bytes.Equal([]byte(got), []byte("NF-TEST1")) {
		t.Fatalf("decryptUserPassword() = %q, want NF-TEST1", got)
	}
}
