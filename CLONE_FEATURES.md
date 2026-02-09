# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P1 (selected): Web UI safe export/redaction helper for bug reports: signature redaction + payload claim masking + one-click copy (never include key material).
- [ ] P1 (selected): Expand Web UI algorithm surface area beyond defaults (HS384/HS512, RS384/RS512, PS256/PS384/PS512, ES384/ES512) with curve-appropriate key presets and tests to prevent key-type confusion.
- [ ] P1 (selected): Release/version hygiene: single-source CLI `--version` + automated checks for changelog/version sync (and basic dependency pin drift guard).
- [ ] P2 (selected): Web server hardening: add CSP + clickjacking defense headers and extend integration tests.
- [ ] P2: Add optional `--jwks-url` fetch + cache for common OIDC/JWKS workflows (explicit opt-in; still works offline via cache).
- [ ] P3: Web UI parity: add a "Claims table" view (like jwt.io) with human-time rendering for `exp`/`nbf`/`iat`.
- [ ] P3: Add verify-time override for debugging (`--at` / web advanced option) without mutating system clock.
- [ ] P3: Add import/export support for saved offline workbench sessions (never persist private keys by default; explicit opt-in only).
- [ ] P3: Publish a minimal JSON schema for API responses and lock it in tests to prevent accidental breaking changes.

## Implemented
- [x] 2026-02-09: ES256 + EdDSA sign/verify support (CLI + web) with safe key parsing for PEM/JWK/JWKS and compatibility tests.
  Evidence: `src/jwt_workbench/core.py`, `src/jwt_workbench/cli.py`, `src/jwt_workbench/web.py`, `src/jwt_workbench/samples.py`, `tests/test_jwt_core.py`.
- [x] 2026-02-09: Web UI adds EC/OKP presets + JWK/JWKS templates for ES256/EdDSA to reduce key-format friction.
  Evidence: `src/jwt_workbench/web.py`, `src/jwt_workbench/samples.py`, `tests/test_web_api.py`.
- [x] 2026-02-09: Verification policy profiles (`legacy`, `default`, `strict`) as fast presets (CLI flag + web UI picker) without changing the default behavior.
  Evidence: `src/jwt_workbench/cli.py`, `src/jwt_workbench/web.py`, `tests/test_smoke.py`.
- [x] 2026-02-09: Copy-safe bug-report export helper (CLI) that redacts JWT signatures by default and emits a shareable JSON bundle (header/payload/warnings).
  Evidence: `src/jwt_workbench/core.py`, `src/jwt_workbench/cli.py`, `tests/test_jwt_core.py`, `tests/test_smoke.py`.
- [x] 2026-02-08: Required-claims verification policy across core, CLI (`--require`), and web API/UI.
  Evidence: `src/jwt_workbench/core.py`, `src/jwt_workbench/cli.py`, `src/jwt_workbench/web.py`, `tests/test_jwt_core.py`, `tests/test_smoke.py`, `tests/test_web_api.py`.
- [x] 2026-02-08: Web API hardening with JSON content-type enforcement, body-size cap, defensive body handling, and no-store security headers.
  Evidence: `src/jwt_workbench/web.py`, `tests/test_web_api.py`.
- [x] 2026-02-08: Shared sample/key-preset generation helpers used by both CLI and web.
  Evidence: `src/jwt_workbench/samples.py`, `src/jwt_workbench/cli.py`, `src/jwt_workbench/web.py`.
- [x] 2026-02-08: CLI key-source validation improvements and strict `alg=none` signing behavior.
  Evidence: `src/jwt_workbench/cli.py`, `tests/test_smoke.py`.
- [x] 2026-02-08: Added integration coverage for live web-serving smoke path and API behavior.
  Evidence: `tests/test_smoke.py`, `tests/test_web_api.py`.

## Insights
- PyJWT `options.require` gives low-cost, high-value security posture improvement when exposed cleanly in CLI/web.
- Request-size and content-type guards are critical for local tooling too because JWT/key payloads are user-controlled.
- Centralizing sample/key preset generation prevents behavior drift across CLI and web features.
- JWK/JWKS key-type enforcement (`kty` vs `alg`) prevents accidental key confusion when users paste the wrong material.
- Policy profiles are most useful when opt-in and client-side in the web UI (no API schema churn), while CLI can apply them server-side safely.
- Market scan (bounded): jwt.io debugger sets baseline UX expectations: decode + encode in one page, copy/clear, and optional signature verification with JSON/claims-table views. https://www.jwt.io/
- Market scan (bounded): Burp's `jwt-editor` indicates "advanced" competitor territory (JWE encrypt/decrypt + attack automation) that jwt-workbench should not copy, but it highlights that safe key handling and explicit algorithm controls are core. https://github.com/PortSwigger/jwt-editor
- Market scan (bounded): `jwt_tool` is explicitly a pentesting toolkit (attacks, fuzzing, dictionary cracking); jwt-workbench should remain a developer-safe offline tool but can borrow defensive UX (clear warnings for alg=none, HS secrets, aud/iss). https://github.com/ticarpi/jwt_tool
- Market scan (bounded): Common JWT ecosystems support a wider set of JWS algs beyond HS256/RS256/ES256, notably HS384/HS512, RS384/RS512, ES384/ES512, and PS256/PS384/PS512. https://jwtauditor.com/docs/reference/jwt-algorithms.html

## Gap Map (Against Comparable Tools)

- Missing:
  - Web UI safe export with claim masking for bug reports (jwt.io has copy helpers but not "safe bundle" semantics).
  - Wider algorithm dropdown coverage (HS/RS/ES variants, PS*).
- Weak:
  - "Claims table" rendering and human-time display for time claims (jwt.io parity).
- Parity:
  - Decode/verify/sign basics; JWKS key selection; copy/clear UX.
- Differentiators:
  - Offline-first, explicit claim policy profiles + required-claims controls, and copy-safe signature redaction.

## Notes
- This file is maintained by the autonomous clone loop.
