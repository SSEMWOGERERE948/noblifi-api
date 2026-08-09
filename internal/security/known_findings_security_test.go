//go:build securityknown

package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func source(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func finding(t *testing.T, id, message, remediation string) {
	t.Helper()
	t.Errorf("%s CONFIRMED: %s\nREMEDIATION: %s", id, message, remediation)
}

// These tests deliberately fail while the documented vulnerabilities exist.
// They are invoked only by `go test -tags=securityknown ./internal/security`.
func TestNS001UnauthenticatedPaymentRoutes(t *testing.T) {
	text := source(t, filepath.Join("payments", "handler.go"))
	if strings.Contains(text, "router.Post(\"/payments/orders\", h.startOrder)") &&
		!strings.Contains(text, "requireUser") {
		finding(t, "NS-001", "payment order, order-status, and callback routes are registered without application authentication or ownership checks.", "Require an authenticated purchaser for order creation/status, bind PaymentOrder to that user, and restrict status results to its owner or an authorized administrator.")
	}
}

func TestNS002UnsignedReplayableWebhook(t *testing.T) {
	text := source(t, filepath.Join("payments", "handler.go"))
	if strings.Contains(text, "func (h *Handler) callback") && !strings.Contains(text, "Signature") {
		finding(t, "NS-002", "the ioTec callback accepts caller-selected transaction identifiers without signature, timestamp, or replay validation.", "Verify the provider's documented signature over the raw body, enforce a timestamp/nonce replay window, persist idempotency state, and reject unsigned callbacks before status processing.")
	}
}

func TestNS003PublicAdministrativeNetworkRoutes(t *testing.T) {
	text := source(t, filepath.Join("radius", "handler.go"))
	if strings.Contains(text, "router.Post(\"/radius/plans/sync\"") && !strings.Contains(text, "requireUser") {
		finding(t, "NS-003", "RADIUS synchronization and accounting endpoints are registered without authentication or authorization.", "Apply centralized authentication and a least-privilege admin role check to every RADIUS, voucher, plan, dashboard, and router-management endpoint.")
	}
}

func TestNS004DevConfirmationCodeExposure(t *testing.T) {
	text := source(t, filepath.Join("auth", "handler.go"))
	if strings.Contains(text, "\"dev_code\":   code") {
		finding(t, "NS-004", "confirmation codes are returned in API responses.", "Deliver codes through a production notification provider only; remove them from responses and logs, rate-limit attempts, and invalidate prior codes on issuance.")
	}
}

func TestNS005InsecureDefaultsAndPublicDebugSurface(t *testing.T) {
	config := source(t, filepath.Join("config", "config.go"))
	server := source(t, filepath.Join("server", "server.go"))
	if strings.Contains(config, "\"change-this-secret\"") || strings.Contains(server, "app.Get(\"/debug/routes\"") {
		finding(t, "NS-005", "a predictable JWT fallback and/or public debug route is present.", "Fail startup when mandatory secrets are missing, rotate exposed credentials, remove debug routes from production, and add environment-specific access controls.")
	}
}

func TestNS006PermissiveCORS(t *testing.T) {
	server := source(t, filepath.Join("server", "server.go"))
	if strings.Contains(server, "AllowOrigins: \"*\"") {
		finding(t, "NS-006", "the API permits every browser origin to send authorized cross-origin requests.", "Use an explicit production origin allowlist, limit methods/headers, and avoid credentialed cross-origin access unless strictly required.")
	}
}
