# API advisory finding catalog

| Finding | Failing test | Remediation completion condition |
| --- | --- | --- |
| NS-001 | `TestNS001UnauthenticatedPaymentRoutes` | Purchaser authentication and database-backed ownership checks reject unauthenticated and cross-user order access. |
| NS-002 | `TestNS002UnsignedReplayableWebhook` | Invalid signatures, stale timestamps, duplicate event IDs, and transaction substitution are rejected before any voucher is issued. |
| NS-003 | `TestNS003PublicAdministrativeNetworkRoutes` | Anonymous and non-admin calls to RADIUS, voucher, plan, dashboard, and router-control APIs receive 401/403. |
| NS-004 | `TestNS004DevConfirmationCodeExposure` | API responses/logs omit codes and delivery/attempt limits are covered by passing tests. |
| NS-005 | `TestNS005InsecureDefaultsAndPublicDebugSurface` | Startup rejects missing secrets; credentials are rotated and removed from tracked current/history material under an approved incident plan; debug routes are absent or protected. |
| NS-006 | `TestNS006PermissiveCORS` | Production CORS returns only reviewed dashboard origins and minimal headers/methods. |

Do not mark a finding resolved merely by changing this catalog or excluding a scanner result. Replace its advisory test with a passing behavior-level regression test after remediation evidence is reviewed.
