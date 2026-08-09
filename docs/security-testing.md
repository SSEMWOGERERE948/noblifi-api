# API security testing

## Safety

Run tests only against a disposable local PostgreSQL database or the GitHub Actions PostgreSQL service. Do not point `DATABASE_URL` at production, use payment credentials, contact an ioTec endpoint, connect to a router, or run a network scan. Payment and TLS cases use local mocks only.

The standard passing checks are:

```powershell
go test ./internal/security
go vet ./...
go build ./cmd/server
```

The complete existing suite is intentionally separate because the repository currently has unrelated failures in `internal/portprofiles`:

```powershell
go test ./...
```

## Known-findings suite

The following command intentionally exits non-zero while documented vulnerabilities remain:

```powershell
go test -tags=securityknown ./internal/security
```

Every failure starts with an `NS-` finding ID and includes the affected security property plus a concrete remediation. It must not be skipped, rewritten to pass, or made required until the underlying issue is remediated. Once fixed, move the assertion into the standard suite and update the audit report with evidence.

## Tooling

CI runs `go vet`, `govulncheck`, Semgrep rules in `.semgrep/security.yml`, Gitleaks, and Go tests. Install optional local tooling with:

```powershell
go install golang.org/x/vuln/cmd/govulncheck@latest
python -m pip install semgrep
```

Use a pre-created test-only PostgreSQL database with an unprivileged test role. No `.env` file is required or created by this baseline.
