# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P1: CLI `verify --oidc-issuer <issuer>` to auto-discover `jwks_uri` via OIDC discovery (explicit opt-in network; allow offline fallback via `--jwks-cache`). [impact=4 effort=3 fit=4 diff=2 risk=3 conf=3]
- [ ] P1: CLI `--quiet` for scripting to suppress warning lines and extra text output (where applicable) without changing JSON payload shapes. [impact=3 effort=2 fit=4 diff=1 risk=2 conf=3]
- [ ] P2: DX: add `make fmt` to apply Ruff formatting locally (reduce CI-only format drift). [impact=2 effort=1 fit=4 diff=1 risk=1 conf=4]
- [ ] P3: Add import/export support for saved offline workbench sessions (never persist private keys by default; explicit opt-in only). [impact=4 effort=4 fit=4 diff=3 risk=3 conf=3]
- [ ] P3: Add import/export for web UI sessions (token + decoded header/payload + policy controls), with explicit redaction of private key material. [impact=3 effort=4 fit=4 diff=2 risk=3 conf=2]
- [ ] P3: Add an explicit "no-network" mode toggle in web UI that disables any future network-required helpers (defense-in-depth UX). [impact=2 effort=2 fit=3 diff=1 risk=1 conf=3]

## Implemented
- [x] 2026-02-09: CI: add `workflow_dispatch` trigger so CI can be manually re-run during transient GitHub outages.
  Evidence: `.github/workflows/ci.yml`.
- [x] 2026-02-09: Publish a minimal JSON schema for web API responses and validate it in tests to prevent accidental breaking changes.
  Evidence: `schemas/web_api_responses.schema.json`, `tests/test_web_api_schema.py`, `requirements-dev.txt`.
- [x] 2026-02-09: Add warning output for risky JWT headers that can imply network key fetching or special processing in other stacks (`jku`, `x5u`, `crit`).
  Evidence: `src/jwt_workbench/core.py`, `tests/test_jwt_core.py`, `CHANGELOG.md`.
- [x] 2026-02-09: Add `--output json|text` for CLI commands (keep existing defaults) and support `sign --output json`.
  Evidence: `src/jwt_workbench/cli.py`, `tests/test_smoke.py`, `README.md`.
- [x] 2026-02-09: Fix `--at` custom time validation to handle null/non-integer claim types without leaking Python `TypeError`.
  Evidence: `src/jwt_workbench/core.py`, `tests/test_jwt_core.py`.
- [x] 2026-02-09: Add key fingerprints (RFC 7638 JWK thumbprint) for non-HS keys in CLI + web verify responses to confirm expected key selection.
  Evidence: `src/jwt_workbench/core.py`, `src/jwt_workbench/cli.py`, `src/jwt_workbench/web.py`, `tests/test_jwt_core.py`, `tests/test_smoke.py`, `tests/test_web_api.py`, `README.md`.
- [x] 2026-02-09: Add `validate` command (decode + claim hygiene checks) that exits non-zero on issues (CI-friendly; no signature verification).
  Evidence: `src/jwt_workbench/cli.py`, `tests/test_smoke.py`, `README.md`.
- [x] 2026-02-09: Make JWKS cache writes atomic and permission-hardened (best-effort) to avoid partial files.
  Evidence: `src/jwt_workbench/core.py`, `tests/test_jwt_core.py`.
- [x] 2026-02-09: Fix `iat` verification error messaging (distinguish future `iat` vs `nbf` and surface integer-claim errors).
  Evidence: `src/jwt_workbench/core.py`, `tests/test_jwt_core.py`.
- [x] 2026-02-09: Verify-time override for debugging (`--at` in CLI + web advanced option) without mutating system clock.
  Evidence: `src/jwt_workbench/core.py`, `src/jwt_workbench/cli.py`, `src/jwt_workbench/web.py`, `tests/test_jwt_core.py`, `tests/test_web_api.py`.
- [x] 2026-02-09: Optional `--jwks-url` fetch + cache for common OIDC/JWKS workflows (explicit opt-in; safe fallback to cache when offline).
  Evidence: `src/jwt_workbench/core.py`, `src/jwt_workbench/cli.py`, `tests/test_jwt_core.py`.
- [x] 2026-02-09: Web UI "Claims table" view (jwt.io parity) with human-time rendering for `exp`/`nbf`/`iat`.
  Evidence: `src/jwt_workbench/web.py`.
- [x] 2026-02-09: Web UI safe export helper: signature redaction + optional payload claim masking + one-click copy (never includes key material).
  Evidence: `src/jwt_workbench/web.py`, `tests/test_web_api.py`.
- [x] 2026-02-09: Expanded algorithm coverage in web UI (HS/RS/PS/ES variants) with curve-appropriate presets and compatibility tests.
  Evidence: `src/jwt_workbench/web.py`, `src/jwt_workbench/samples.py`, `src/jwt_workbench/cli.py`, `tests/test_jwt_core.py`, `tests/test_web_api.py`, `README.md`.
- [x] 2026-02-09: Release/version hygiene: CLI `--version` reads package metadata + `make release-check` validates changelog/version sync and pinned deps.
  Evidence: `src/jwt_workbench/version.py`, `src/jwt_workbench/cli.py`, `scripts/release_check.py`, `Makefile`.
- [x] 2026-02-09: Web hardening: CSP + anti-embed headers with test coverage.
  Evidence: `src/jwt_workbench/web.py`, `tests/test_web_api.py`.
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
- Publishing a minimal web API schema plus tests acts like a low-overhead contract to prevent accidental response churn as features evolve.
- Market scan (bounded): jwt.io sets the baseline single-page debugger UX (encode/decode side-by-side, copy/clear, optional signature verification). https://jwt.io/
- Market scan (bounded): jwt.ms is a widely used “paste a token” viewer (common in Azure/Microsoft ecosystems) with a fast decode-first workflow baseline. https://jwt.ms/
- Market scan (bounded): token.dev positions as a modern token debugger emphasizing safe copy/share workflows and quick claim inspection. https://token.dev/
- Market scan (bounded): OIDC issuers commonly publish `jwks_uri` via discovery (`/.well-known/openid-configuration`) which tools often support to reduce setup friction. https://openid.net/specs/openid-connect-discovery-1_0.html
- Market scan (bounded): Developer docs commonly describe JWKS + rotation workflows and emphasize `kid` selection as the stable way to pick keys. https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets
- Market scan (bounded): RFC 7638 defines a standard JWK thumbprint (SHA-256) for computing stable key fingerprints from public JWK fields. https://www.rfc-editor.org/rfc/rfc7638

## Gap Map (Against Comparable Tools)

- Missing:
  - CLI `validate` / lint mode for CI-friendly claim hygiene checks (without requiring signature keys).
  - Key fingerprint visibility (public-only) to reduce “did I paste the right key?” confusion.
  - OIDC discovery helper to auto-resolve `jwks_uri` from an issuer (opt-in network).
  - Import/export saved sessions for offline workflows (safe defaults: never persist private keys).
- Weak:
  - CLI ergonomics for terminal use (optional text output, compact views).
- Parity:
  - Decode/verify/sign basics; JWKS key selection; copy/clear UX.
- Differentiators:
  - Offline-first, explicit claim policy profiles + required-claims controls, and copy-safe signature redaction.

## Notes
- This file is maintained by the autonomous clone loop.
