package security

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/noblifi/noblifi/backend/internal/auth"
)

// These passing tests protect security properties that are already enforced by
// the authentication implementation. Known vulnerable behavior is tested only
// under the securityknown build tag so normal test runs are useful as gates.
func TestRejectsUnsignedJWT(t *testing.T) {
	svc := auth.NewService(nil, "security-test-secret")
	raw, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "00000000-0000-0000-0000-000000000001",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UserFromToken(raw); err == nil {
		t.Fatal("unsigned JWT was accepted")
	}
}

func TestRejectsExpiredJWT(t *testing.T) {
	svc := auth.NewService(nil, "security-test-secret")
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "00000000-0000-0000-0000-000000000001",
		"exp": time.Now().Add(-time.Minute).Unix(),
	}).SignedString([]byte("security-test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UserFromToken(raw); err == nil {
		t.Fatal("expired JWT was accepted")
	}
}
