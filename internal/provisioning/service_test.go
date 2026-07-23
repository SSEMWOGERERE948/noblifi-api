package provisioning

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
	"github.com/noblifi/noblifi/backend/internal/routers"
)

func TestRenderHotspotLoginPageShowsVoucherLoginAndPackages(t *testing.T) {
	html := renderHotspotLoginPage("NobliFi WiFi", []plans.Plan{
		{
			ID:              uuid.New(),
			Name:            "Daily Unlimited",
			Price:           1000,
			DurationMinutes: 1440,
			DownloadSpeed:   "10M",
			IsActive:        true,
		},
	})

	required := []string{
		"NobliFi WiFi",
		"Enter your voucher code to connect.",
		`<input id="username" name="username" autocomplete="one-time-code" placeholder="NF-XXXXXXXX" autofocus>`,
		`<input id="password" name="password" type="hidden">`,
		"Your voucher code is used for both username and password.",
		"Packages",
		"Daily Unlimited",
		"UGX 1,000",
	}
	for _, item := range required {
		if !strings.Contains(html, item) {
			t.Fatalf("expected hotspot login page to contain %q, got:\n%s", item, html)
		}
	}

	forbidden := []string{"password\" type=\"password"}
	for _, item := range forbidden {
		if strings.Contains(html, item) {
			t.Fatalf("hotspot login page must not contain %q, got:\n%s", item, html)
		}
	}
}

type radiusRegistration struct {
	nasName string
}

func (r *radiusRegistration) RegisterNAS(nasName, shortName, secret, description string) error {
	r.nasName = nasName
	return nil
}

func TestRegisterRadiusNASPrefersWireGuardTunnelAddress(t *testing.T) {
	tunnelIP := "10.77.0.12"
	registrar := &radiusRegistration{}
	service := Service{radius: registrar}
	router := routers.Router{Name: "Branch", WireGuardTunnelIP: &tunnelIP}
	options := portprofiles.RenderOptions{RouterIdentity: "NobliFi-Branch", RadiusSecret: "noblifi"}

	if err := service.registerRadiusNAS(router, options, "198.51.100.20"); err != nil {
		t.Fatalf("register NAS: %v", err)
	}
	if registrar.nasName != tunnelIP {
		t.Fatalf("expected tunnel NAS address %q, got %q", tunnelIP, registrar.nasName)
	}
}

func TestRenderHotspotLoginPageEscapesPortalName(t *testing.T) {
	rawName := `<script>alert("x")</script>`
	html := renderHotspotLoginPage(rawName, nil)

	if strings.Contains(html, `<h1>`+rawName+`</h1>`) || strings.Contains(html, `<title>`+rawName+` Login</title>`) {
		t.Fatalf("expected portal name to be escaped, got:\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;") {
		t.Fatalf("expected escaped portal name, got:\n%s", html)
	}
}
