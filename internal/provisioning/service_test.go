package provisioning

import (
	"strings"
	"testing"

	"github.com/noblifi/noblifi/backend/internal/plans"
)

func TestRenderHotspotLoginPageIncludesActivePackages(t *testing.T) {
	html := renderHotspotLoginPage([]plans.Plan{
		{
			Name:            "Daily Unlimited",
			Price:           3000,
			DurationMinutes: 1440,
			DownloadSpeed:   "10M",
			UploadSpeed:     "5M",
			MaxDevices:      2,
		},
	})

	required := []string{
		"NobliFi WiFi",
		"Daily Unlimited",
		"UGX 3,000",
		"1 day access",
		"10M down / 5M up",
		"Use the same voucher code for username and password",
	}
	for _, item := range required {
		if !strings.Contains(html, item) {
			t.Fatalf("expected hotspot login page to contain %q, got:\n%s", item, html)
		}
	}
}
