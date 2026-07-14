package provisioning

import (
	"strings"
	"testing"
)

func TestRenderHotspotLoginPageIsVoucherOnlyNobliFiPortal(t *testing.T) {
	html := renderHotspotLoginPage("NobliFi WiFi")

	required := []string{
		"NobliFi WiFi",
		"Enter your voucher code to connect.",
		`<input id="username" name="username" autocomplete="one-time-code" placeholder="NF-XXXXXXXX" autofocus>`,
		`<input id="password" name="password" type="hidden">`,
		"Your voucher code is used for both username and password.",
	}
	for _, item := range required {
		if !strings.Contains(html, item) {
			t.Fatalf("expected hotspot login page to contain %q, got:\n%s", item, html)
		}
	}

	forbidden := []string{"password\" type=\"password", "Daily Unlimited", "Packages"}
	for _, item := range forbidden {
		if strings.Contains(html, item) {
			t.Fatalf("voucher-only hotspot login page must not contain %q, got:\n%s", item, html)
		}
	}
}

func TestRenderHotspotLoginPageEscapesPortalName(t *testing.T) {
	rawName := `<script>alert("x")</script>`
	html := renderHotspotLoginPage(rawName)

	if strings.Contains(html, `<h1>`+rawName+`</h1>`) || strings.Contains(html, `<title>`+rawName+` Login</title>`) {
		t.Fatalf("expected portal name to be escaped, got:\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;") {
		t.Fatalf("expected escaped portal name, got:\n%s", html)
	}
}
