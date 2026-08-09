# NobliFi API Security Audit

**Assessment status:** baseline source review and deterministic regression checks. Findings are deliberately not remediated by this change.

## Architecture and trust boundaries

The deployed API is Go/Fiber with GORM/PostgreSQL. The Next.js dashboard sends bearer tokens to `/api/v1`. API services manage users, plans, vouchers, payments, FreeRADIUS tables, MikroTik provisioning/configuration, WireGuard agent jobs, and router telemetry. ioTec is an external payment boundary; MikroTik, RADIUS, WireGuard agents, and the VPS are network-control boundaries. The repository also retains legacy Node/Express/SQLite/RADIUS code that must not be deployed unintentionally.

Sensitive assets include password hashes, JWTs, confirmation codes, payment references/provider responses, phone/email data, router claim tokens, RADIUS secrets, RouterOS credentials, WireGuard agent tokens/keys, and database/cloud credentials.

Primary flows are: browser → API → PostgreSQL; API → ioTec; dashboard/API → router provisioning scripts → MikroTik/RADIUS/WireGuard agent; and agent → internal API. Public provisioning URLs and payment callbacks are particularly sensitive trust boundaries.

## Confirmed findings

| ID | Severity / CVSS rationale | Component | Evidence and impact | Security test | Recommended remediation |
| --- | --- | --- | --- | --- | --- |
| NS-001 | High (CVSS 8.1: network, low complexity, payment/data integrity) | `internal/payments/handler.go` | Payment creation and status routes have no user authentication or order ownership authorization. | `TestNS001UnauthenticatedPaymentRoutes` | Authenticate purchaser routes; persist owner ID; authorize every read; return minimum payment state. |
| NS-002 | High (CVSS 8.2: network payment integrity) | `internal/payments/handler.go` | Callback accepts identifiers from query/body without a provider signature, timestamp, nonce, or callback replay ledger. | `TestNS002UnsignedReplayableWebhook` | Validate documented HMAC/signature on raw body, timestamp and nonce; enforce idempotency atomically. |
| NS-003 | Critical (CVSS 9.1: unauthenticated network/service control) | `internal/radius/handler.go`, plan/voucher/dashboard routes | RADIUS management and other operational APIs are registered without an authorization boundary. | `TestNS003PublicAdministrativeNetworkRoutes` | Default-deny API middleware; explicit roles and ownership checks. |
| NS-004 | High (CVSS 7.5: account-protection bypass) | `internal/auth/handler.go` | Confirmation codes are returned as `dev_code` to the requester. | `TestNS004DevConfirmationCodeExposure` | Deliver out-of-band only; remove response/log exposure; rate-limit and expire attempts. |
| NS-005 | Critical (CVSS 9.8 if deployed with defaults/exposed secrets) | `config`, `auth`, `server`, configuration/history | Predictable JWT fallback, seeded administrator credentials, public route listing, tracked environment data, and hard-coded deployment credentials were observed. Values are intentionally omitted. | `TestNS005InsecureDefaultsAndPublicDebugSurface`; Gitleaks advisory | Rotate affected secrets immediately, remove tracked secret material/history under an approved rotation plan, prohibit defaults, and remove/restrict debug endpoints. |
| NS-006 | Medium (CVSS 6.5: cross-origin attack surface) | `internal/server/server.go` | CORS allows every origin and broad methods/authorization header. | `TestNS006PermissiveCORS` | Configure explicit trusted origins and minimal methods/headers. |
| NS-007 | Medium (browser token theft impact) | Frontend authentication storage | Bearer JWT is persisted in browser local storage, exposing it to successful XSS. | Frontend `NS-007` advisory test | Prefer secure, `HttpOnly`, `Secure`, `SameSite` cookies with CSRF protections and strong CSP. |

## Additional assessed risks

SQL injection is mitigated in reviewed GORM parameterized calls, but input boundaries need API-level tests. RouterOS script generation and direct MikroTik connections require continuing command/script-injection and SSRF/private-address tests. Payment provider requests use HTTP client defaults, but sensitive endpoint URLs must be restricted to HTTPS and certificate validation must never be disabled. No real MITM, payment, Wi-Fi, or router testing is performed by CI.

## Standards mapping

Relevant mappings include OWASP Top 10 A01/A02/A05/A07/A10; OWASP API Top 10 API1, API2, API5, API7, API8; OWASP ASVS V2, V3, V4, V7, V9, V13; CWE-306, CWE-284, CWE-798, CWE-489, CWE-200, CWE-319, CWE-345, and CWE-862. CVSS scores are preliminary and should be recalibrated with deployment reachability and provider webhook contract details.

## Scope limitations

This audit does not prove absence of vulnerabilities, inspect external cloud/account settings, or test a live payment gateway, router, Wi-Fi network, or VPS. Legacy Node code is in scope for static review because it remains in the repository, but Go is the configured deployment runtime. All listed vulnerabilities remain unfixed by design.
