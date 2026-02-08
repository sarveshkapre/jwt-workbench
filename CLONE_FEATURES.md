# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P1: Add ES256 and EdDSA support for sign/verify with safe key handling and compatibility tests.
- [ ] P1: Add copy-safe JWT redaction/export helpers (mask signatures/secrets by default for sharing/debugging).
- [ ] P2: Add verification policy profiles (`strict`, `default`, `legacy`) for faster secure onboarding.
- [ ] P2: Add release automation checks for pinned dependency drift and changelog/version sync.
- [ ] P3: Add import/export support for saved offline workbench sessions (without persisting private keys by default).

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
