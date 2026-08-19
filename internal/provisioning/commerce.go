package provisioning

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strings"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/payments"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/routers"
)

type TenantPlanLister interface {
	ActiveListForUser(userID uuid.UUID) ([]plans.Plan, error)
}

type HotspotPaymentService interface {
	StartHotspotOrder(input payments.HotspotOrderInput) (payments.HotspotOrderResult, error)
	CheckHotspotOrder(input payments.HotspotOrderStatusInput) (payments.HotspotOrderStatusResult, error)
}

func (s *Service) SetPlanLister(value TenantPlanLister)                 { s.plans = value }
func (s *Service) SetHotspotPaymentService(value HotspotPaymentService) { s.hotspotPayments = value }

type HotspotBuyInput struct{ PlanID, Phone, Email, DeviceMAC string }

func (s *Service) HotspotBuy(token string, input HotspotBuyInput) (payments.HotspotOrderResult, error) {
	router, ownerID, err := s.hotspotPurchaseScope(token)
	if err != nil {
		return payments.HotspotOrderResult{}, err
	}
	if s.hotspotPayments == nil {
		return payments.HotspotOrderResult{}, errors.New("online hotspot payment is unavailable")
	}
	planID, err := uuid.Parse(strings.TrimSpace(input.PlanID))
	if err != nil {
		return payments.HotspotOrderResult{}, errors.New("invalid plan id")
	}
	return s.hotspotPayments.StartHotspotOrder(payments.HotspotOrderInput{
		OwnerUserID: ownerID, RouterID: router.ID, PlanID: planID,
		DeviceMAC: strings.TrimSpace(input.DeviceMAC), Phone: strings.TrimSpace(input.Phone), Email: strings.TrimSpace(input.Email),
	})
}

func (s *Service) HotspotBuyStatus(token, paymentID, deviceMAC string) (payments.HotspotOrderStatusResult, error) {
	router, ownerID, err := s.hotspotPurchaseScope(token)
	if err != nil {
		return payments.HotspotOrderStatusResult{}, err
	}
	if s.hotspotPayments == nil {
		return payments.HotspotOrderStatusResult{}, errors.New("online hotspot payment is unavailable")
	}
	return s.hotspotPayments.CheckHotspotOrder(payments.HotspotOrderStatusInput{
		OwnerUserID: ownerID, RouterID: router.ID, PaymentID: strings.TrimSpace(paymentID), DeviceMAC: strings.TrimSpace(deviceMAC),
	})
}

func (s *Service) hotspotPurchaseScope(token string) (routers.Router, uuid.UUID, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return routers.Router{}, uuid.Nil, errors.New("claim token is required")
	}
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return routers.Router{}, uuid.Nil, errors.New("invalid claim token")
	}
	if router.UserID == nil || *router.UserID == uuid.Nil {
		return routers.Router{}, uuid.Nil, errors.New("hotspot router has no account owner")
	}
	return router, *router.UserID, nil
}

func (s *Service) activePortalPlans(router routers.Router) ([]plans.Plan, error) {
	if router.UserID == nil || *router.UserID == uuid.Nil {
		return nil, errors.New(
			"hotspot router has no account owner",
		)
	}

	if s.plans == nil {
		return nil, errors.New(
			"hotspot plan service is not configured; call SetPlanLister during server startup",
		)
	}

	items, err := s.plans.ActiveListForUser(*router.UserID)
	if err != nil {
		return nil, fmt.Errorf(
			"load active hotspot packages for user %s: %w",
			router.UserID.String(),
			err,
		)
	}

	return items, nil
}

func (s *Service) renderHotspotManualCommercePage(router routers.Router, token, portalName, authURL, deviceMAC, linkLogin, linkOrig, message string) (string, error) {
	items, err := s.activePortalPlans(router)
	if err != nil {
		return "", fmt.Errorf("load hotspot packages: %w", err)
	}
	return renderHotspotCommercePage(portalName, authURL,
		normalizeProvisioningBaseURL(s.cfg.ProvisioningBaseURL)+"/hotspot-buy/"+strings.TrimSpace(token),
		normalizeProvisioningBaseURL(s.cfg.ProvisioningBaseURL)+"/hotspot-buy/"+strings.TrimSpace(token)+"/",
		deviceMAC, linkLogin, linkOrig, message, items, s.hotspotPayments != nil), nil
}

func renderHotspotCommercePage(portalName, authURL, buyURL, statusBase, deviceMAC, linkLogin, linkOrig, message string, items []plans.Plan, paymentsEnabled bool) string {
	if strings.TrimSpace(portalName) == "" {
		portalName = "NobliFi WiFi"
	}

	packages := renderPortalPackageCards(items, paymentsEnabled)

	notice := ""
	if strings.TrimSpace(message) != "" {
		notice = `<div class="notice">` +
			html.EscapeString(strings.TrimSpace(message)) +
			`</div>`
	}

	j := func(v string) string {
		b, _ := json.Marshal(v)
		return string(b)
	}

	return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#06111f">
<title>` + html.EscapeString(portalName) + ` Login</title>
<style>
:root{color-scheme:dark;--bg:#06111f;--panel:#0b1727;--line:#24384f;--text:#f8fbff;--muted:#9fb0c5;--brand:#7dd3fc;--accent:#34d399;--warn:#fde68a}
*{box-sizing:border-box}
body{margin:0;font-family:Arial,Helvetica,sans-serif;background:linear-gradient(145deg,#06111f 0%,#0b1727 52%,#102033 100%);color:var(--text)}
main{min-height:100vh;padding:24px 16px 40px}
.shell{width:min(980px,100%);margin:0 auto}
.hero{text-align:center;margin:18px 0 22px}
.mark{width:52px;height:52px;display:grid;place-items:center;margin:0 auto 14px;border-radius:12px;background:var(--brand);color:#06111f;font-weight:900}
.eyebrow{margin:0 0 7px;color:var(--brand);font-size:11px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}
h1{margin:0;font-size:32px}
.sub{color:var(--muted);margin:9px auto 0;max-width:620px;line-height:1.5}
.grid{display:grid;grid-template-columns:minmax(0,.85fr) minmax(0,1.35fr);gap:18px;align-items:start}
.panel{border:1px solid var(--line);background:rgba(11,23,39,.94);border-radius:14px;padding:22px;box-shadow:0 18px 50px rgba(0,0,0,.24)}
h2{margin:0 0 8px;font-size:19px}
label{display:block;margin:18px 0 8px;font-weight:700;font-size:14px}
input{width:100%;border:1px solid var(--line);background:#07111d;color:var(--text);border-radius:9px;padding:13px;font-size:16px}
button{border:0;border-radius:9px;padding:12px 14px;font-weight:800;cursor:pointer}
button:disabled{opacity:.55;cursor:not-allowed}
.primary{width:100%;margin-top:14px;background:var(--brand);color:#06111f}
.buy{background:var(--accent);color:#04150f}
.hint{color:var(--muted);font-size:12px;line-height:1.45;margin:12px 0 0}
.notice{margin:14px 0;padding:11px 13px;border:1px solid rgba(253,230,138,.25);background:rgba(253,230,138,.07);border-radius:10px;color:var(--warn);font-size:13px}
.packages{display:grid;gap:11px;margin-top:16px}
.package{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:14px;align-items:center;padding:15px;border:1px solid var(--line);border-radius:11px;background:#081421}
.package strong{display:block}
.meta{margin-top:5px;display:flex;flex-wrap:wrap;gap:6px 12px;color:var(--muted);font-size:12px}
.price{margin-top:8px;font-weight:900}
.empty{padding:16px;border:1px dashed var(--line);border-radius:10px;color:var(--muted);text-align:center}
.purchase{display:none;margin-top:18px;padding-top:18px;border-top:1px solid var(--line)}
.purchase.open{display:block}
.payment-message{min-height:18px;margin-top:12px;color:var(--muted);font-size:13px}
.secure{text-align:center;color:var(--muted);font-size:11px;margin-top:20px}
@media(max-width:760px){.grid{grid-template-columns:1fr}.package{grid-template-columns:1fr}.buy{width:100%}}
</style>
</head>
<body>
<main>
<div class="shell">
<header class="hero">
<div class="mark">NF</div>
<p class="eyebrow">WiFi Access</p>
<h1>` + html.EscapeString(portalName) + `</h1>
<p class="sub">Use an existing voucher or buy an active package securely with mobile money.</p>
</header>

<div class="grid">
<section class="panel">
<h2>Have a voucher?</h2>
<p class="hint">Enter it once. It stays assigned to this device until time or data expires.</p>
` + notice + `
<form id="voucher-form" action="` + html.EscapeString(authURL) + `" method="post">
<input type="hidden" name="mac" value="` + html.EscapeString(deviceMAC) + `">
<input type="hidden" name="link_login" value="` + html.EscapeString(linkLogin) + `">
<input type="hidden" name="link_orig" value="` + html.EscapeString(linkOrig) + `">
<label for="voucher_code">Voucher code</label>
<input id="voucher_code" name="voucher_code" autocomplete="one-time-code" placeholder="NF-XXXXXXXX" required>
<button class="primary" id="voucher-connect-button" type="submit">Connect</button>
</form>
</section>

<section class="panel">
<h2>Buy access online</h2>
<p class="hint">Only active packages for this HotSpot are shown.</p>
` + packages + `
<div class="purchase" id="purchase-panel">
<h2 id="selected-package">Complete payment</h2>
<form id="purchase-form">
<label for="buyer-phone">Mobile money phone</label>
<input id="buyer-phone" inputmode="tel" autocomplete="tel" placeholder="2567XXXXXXXX" required>
<label for="buyer-email">Email (optional)</label>
<input id="buyer-email" type="email" autocomplete="email">
<button class="primary" id="pay-button" type="submit">Pay and connect</button>
</form>
<div class="payment-message" id="payment-message"></div>
</div>
</section>
</div>

<p class="secure">Secure WiFi access powered by NobliFi</p>
</div>
</main>

<script>
(function () {
  var AUTH_URL = ` + j(authURL) + `;
  var BUY_URL = ` + j(buyURL) + `;
  var STATUS_BASE = ` + j(statusBase) + `;
  var DEVICE_MAC = ` + j(deviceMAC) + `;
  var LINK_LOGIN = ` + j(linkLogin) + `;
  var LINK_ORIG = ` + j(linkOrig) + `;
  var selectedPlanId = "";

  // Only the newest payment-status loop is allowed to continue.
  var pollGeneration = 0;
  var pollTimer = null;

  function readJSON(response) {
    return response.text().then(function (text) {
      var body = {};
      if (text) {
        try {
          body = JSON.parse(text);
        } catch (_) {
          body = { error: text };
        }
      }

      if (!response.ok) {
        throw new Error(
          body.error ||
          body.message ||
          "Request failed."
        );
      }

      return body;
    });
  }

  function fetchJSONWithTimeout(url, options, timeoutMs) {
    var controller = new AbortController();
    var timer = window.setTimeout(function () {
      controller.abort();
    }, timeoutMs || 10000);

    options = options || {};
    options.signal = controller.signal;

    return fetch(url, options)
      .then(readJSON)
      .catch(function (error) {
        if (error && error.name === "AbortError") {
          throw new Error("The request took too long. Retrying…");
        }
        throw error;
      })
      .finally(function () {
        window.clearTimeout(timer);
      });
  }

  function msg(value) {
    document.getElementById("payment-message").textContent =
      value || "";
  }

  function enabled(value, label) {
    var button = document.getElementById("pay-button");
    button.disabled = !value;
    button.textContent = label || "Pay and connect";
  }

  function stopPolling() {
    pollGeneration++;
    if (pollTimer) {
      window.clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  function login(voucher) {
    stopPolling();

    // This POST remains HTTPS -> HTTPS. The backend then performs a normal
    // browser navigation back to the local HotSpot page. It no longer returns
    // an HTTPS form that directly submits to HTTP, so Chromium's insecure-form
    // interstitial is avoided.
    var form = document.createElement("form");
    form.method = "post";
    form.action = AUTH_URL;
    form.style.display = "none";

    var values = {
      voucher_code: voucher,
      mac: DEVICE_MAC,
      link_login: LINK_LOGIN,
      link_orig: LINK_ORIG
    };

    Object.keys(values).forEach(function (name) {
      var input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = values[name] || "";
      form.appendChild(input);
    });

    document.body.appendChild(form);
    form.submit();
  }

  function schedulePoll(id, remaining, generation) {
    if (generation !== pollGeneration) return;

    pollTimer = window.setTimeout(function () {
      poll(id, remaining, generation);
    }, 3000);
  }

  function poll(id, remaining, generation) {
    if (generation !== pollGeneration) return;

    fetchJSONWithTimeout(
      STATUS_BASE +
        encodeURIComponent(id) +
        "?mac=" +
        encodeURIComponent(DEVICE_MAC),
      { cache: "no-store" },
      8000
    )
      .then(function (result) {
        if (generation !== pollGeneration) return;

        if (result.status === "paid" && result.voucher) {
          msg("Payment confirmed. Connecting...");
          login(result.voucher);
          return;
        }

        if (result.status === "failed") {
          stopPolling();
          enabled(true, "Try payment again");
          msg(result.raw_status || "Payment failed.");
          return;
        }

        if (remaining <= 0) {
          stopPolling();
          enabled(true, "Check / pay again");
          msg(
            "Payment is still pending. If you approved the prompt, try again shortly."
          );
          return;
        }

        schedulePoll(
          id,
          remaining - 1,
          generation
        );
      })
      .catch(function (error) {
        if (generation !== pollGeneration) return;

        if (remaining <= 0) {
          stopPolling();
          enabled(true, "Try again");
          msg(
            error.message ||
            "Could not verify payment."
          );
          return;
        }

        // A timeout/network failure does not permanently stop voucher
        // retrieval. Retry after 3 seconds.
        msg(
          error.message ||
          "Checking payment again…"
        );

        schedulePoll(
          id,
          remaining - 1,
          generation
        );
      });
  }

  function startPolling(id) {
    stopPolling();
    var generation = pollGeneration;
    poll(id, 100, generation);
  }

  document
    .querySelectorAll(".buy-package")
    .forEach(function (button) {
      button.addEventListener(
        "click",
        function () {
          selectedPlanId =
            this.getAttribute(
              "data-plan-id"
            ) || "";

          document.getElementById(
            "selected-package"
          ).textContent =
            "Buy " +
            (
              this.getAttribute(
                "data-plan-name"
              ) || "package"
            );

          document
            .getElementById(
              "purchase-panel"
            )
            .classList.add("open");

          msg("");

          document.getElementById(
            "buyer-phone"
          ).focus();
        }
      );
    });

  document
    .getElementById("voucher-form")
    .addEventListener(
      "submit",
      function () {
        var button =
          document.getElementById(
            "voucher-connect-button"
          );

        if (button.disabled) return;

        button.disabled = true;
        button.textContent = "Connecting...";
      }
    );

  document
    .getElementById("purchase-form")
    .addEventListener(
      "submit",
      function (event) {
        event.preventDefault();

        if (!selectedPlanId) {
          msg("Choose a package first.");
          return;
        }

        if (!DEVICE_MAC) {
          msg(
            "Could not identify this device."
          );
          return;
        }

        var phone =
          document
            .getElementById(
              "buyer-phone"
            )
            .value.trim();

        var email =
          document
            .getElementById(
              "buyer-email"
            )
            .value.trim();

        if (!phone) {
          msg(
            "Enter your mobile money phone number."
          );
          return;
        }

        stopPolling();
        enabled(
          false,
          "Starting payment..."
        );

        fetchJSONWithTimeout(
          BUY_URL,
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/json"
            },
            body: JSON.stringify({
              plan_id:
                selectedPlanId,
              phone: phone,
              email: email,
              mac: DEVICE_MAC
            })
          },
          12000
        )
          .then(function (order) {
            if (
              !order.order_tracking_id
            ) {
              throw new Error(
                "Payment provider did not return an order id."
              );
            }

            enabled(
              false,
              "Waiting for approval..."
            );

            msg(
              "Approve the mobile money prompt. NobliFi will connect automatically."
            );

            startPolling(
              order.order_tracking_id
            );
          })
          .catch(
            function (error) {
              enabled(
                true,
                "Try payment again"
              );

              msg(
                error.message ||
                "Could not start payment."
              );
            }
          );
      }
    );
})();
</script>
</body>
</html>`
}

func renderPortalPackageCards(items []plans.Plan, paymentsEnabled bool) string {
	if len(items) == 0 {
		return `<div class="empty">No packages are available right now.</div>`
	}
	var b strings.Builder
	b.WriteString(`<div class="packages">`)
	shown := 0
	for _, p := range items {
		if !p.IsActive {
			continue
		}
		shown++
		b.WriteString(`<article class="package"><div><strong>` + html.EscapeString(p.Name) + `</strong><div class="meta"><span>` + html.EscapeString(portalPlanDuration(p.DurationMinutes)) + `</span><span>` + html.EscapeString(portalPlanSpeed(p.UploadSpeed, p.DownloadSpeed)) + `</span><span>` + html.EscapeString(portalPlanData(p.DataLimitMB)) + `</span></div><div class="price">UGX ` + formatPortalUGX(p.Price) + `</div></div>`)
		if paymentsEnabled && p.Price > 0 {
			b.WriteString(`<button type="button" class="buy buy-package" data-plan-id="` + html.EscapeString(p.ID.String()) + `" data-plan-name="` + html.EscapeString(p.Name) + `">Buy</button>`)
		} else if p.Price <= 0 {
			b.WriteString(`<span class="hint">Voucher only</span>`)
		} else {
			b.WriteString(`<span class="hint">Online payment unavailable</span>`)
		}
		b.WriteString(`</article>`)
	}
	b.WriteString(`</div>`)
	if shown == 0 {
		return `<div class="empty">No packages are available right now.</div>`
	}
	return b.String()
}
func portalPlanDuration(m int) string {
	if m <= 0 {
		return "Time limited"
	}
	if m%1440 == 0 {
		d := m / 1440
		if d == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", d)
	}
	if m%60 == 0 {
		h := m / 60
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	return fmt.Sprintf("%d minutes", m)
}
func portalPlanSpeed(u, d string) string {
	u = strings.TrimSpace(u)
	d = strings.TrimSpace(d)
	if u == "" && d == "" {
		return "Unlimited speed"
	}
	if u == "" {
		u = d
	}
	if d == "" {
		d = u
	}
	return u + " upload / " + d + " download"
}
func portalPlanData(v *int) string {
	if v == nil || *v <= 0 {
		return "Unlimited data"
	}
	m := *v
	if m%1024 == 0 {
		return fmt.Sprintf("%d GB data", m/1024)
	}
	if m >= 1024 {
		return fmt.Sprintf("%.1f GB data", float64(m)/1024)
	}
	return fmt.Sprintf("%d MB data", m)
}
func formatPortalUGX(a int) string {
	raw := fmt.Sprintf("%d", a)
	if len(raw) <= 3 {
		return raw
	}
	first := len(raw) % 3
	if first == 0 {
		first = 3
	}
	var b strings.Builder
	b.WriteString(raw[:first])
	for i := first; i < len(raw); i += 3 {
		b.WriteString(",")
		b.WriteString(raw[i : i+3])
	}
	return b.String()
}