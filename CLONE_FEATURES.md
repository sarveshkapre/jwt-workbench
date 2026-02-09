# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P1 (Selected): Add ES256 + EdDSA support for sign/verify (CLI + web) with safe key parsing for PEM/JWK/JWKS and compatibility tests.
- [ ] P1 (Selected): Add copy-safe bug-report export helpers (CLI) that redact JWT signatures by default and emit a shareable JSON bundle (header/payload/warnings).
- [ ] P2 (Selected): Add verification policy profiles (`legacy`, `default`, `strict`) as fast presets (CLI flag + web UI picker) without changing the default behavior.
- [ ] P2: Expand algorithm surface area beyond the UI defaults (HS384/HS512, RS384/RS512, ES384/ES512) with tests to prevent key-type confusion.
- [ ] P2: Add EC/OKP JWK/JWKS templates + presets in the web UI to reduce key-format friction for ES256/EdDSA.
- [ ] P2: Add release automation checks for changelog/version sync and dependency pin drift.
- [ ] P3: Add import/export support for saved offline workbench sessions (never persist private keys by default; explicit opt-in only).

## Implemented
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

## Notes
- This file is maintained by the autonomous clone loop.
