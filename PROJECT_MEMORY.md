# Project Memory

This file captures evolving, structured decisions and evidence for `jwt-workbench`.

## Decisions

### 2026-02-09: Enforce JWK/JWKS key type (`kty`) compatibility with JWT `alg`

- Decision: When loading JWK/JWKS for verification, reject keys whose `kty` doesn't match the selected/inferred `alg` (RSA for `RS*`/`PS*`, EC for `ES*`, OKP for `EdDSA`).
- Why: Prevent common key-confusion mistakes (pasting the wrong JWK/JWKS) from degrading into unclear crypto errors or accidental misuse.
- Evidence: Added `_expected_jwk_kty_for_alg()` and `_jwk_to_key()` and updated JWKS selection logic to safely auto-select a unique matching key by `kty` when `kid` is omitted.
- Commit: `e133712`.
- Confidence: High.
- Trust label: Local implementation + tests.

### 2026-02-09: Add opt-in verification policy profiles (no default behavior change)

- Decision: Introduce `legacy/default/strict` profiles as presets rather than changing defaults.
- Why: JWT ecosystems vary widely; tightening defaults would be a breaking behavior change. Presets give a secure on-ramp without surprising existing workflows.
- Evidence: CLI `--policy` (server-side) and web UI policy picker (client-side, no API schema change).
- Commit: `8f0b9a1`.
- Confidence: High.
- Trust label: Local implementation + tests.

### 2026-02-09: Provide copy-safe export for bug reports by redacting JWT signatures

- Decision: Add `jwt-workbench export` to emit a JSON bundle with `token_redacted` plus decoded header/payload/warnings.
- Why: Teams routinely paste tokens into issues; signature redaction reduces accidental leakage risk while preserving debugging context.
- Evidence: `redact_jws_signature()` + CLI `export` command + smoke tests.
- Commit: `14e0987`.
- Confidence: High.
- Trust label: Local implementation + tests.

## Recent Decisions

- 2026-02-09 | Fix verification error messaging for time-claim failures (`iat` vs `nbf`, and integer-claim errors) | Reduce debugging time and prevent misleading messages when PyJWT raises shared exception types | `src/jwt_workbench/core.py`, `tests/test_jwt_core.py` | `c2f1751` | High | trusted
- 2026-02-09 | Add `validate` command for CI-friendly claim hygiene checks (no signature verification) | Provide a fast, offline lint mode that can gate builds without requiring private key material | `src/jwt_workbench/cli.py`, `tests/test_smoke.py`, `README.md` | `4364bc6` | High | trusted
- 2026-02-09 | Add key fingerprints via RFC 7638 JWK thumbprint (non-HS only) | Reduce key-paste confusion and make "did I use the right key?" debugging deterministic without exposing secret material | `src/jwt_workbench/core.py`, `src/jwt_workbench/cli.py`, `src/jwt_workbench/web.py`, `tests/test_jwt_core.py`, `tests/test_web_api.py` | `4364bc6` | High | trusted
- 2026-02-09 | Atomic + permission-hardened JWKS cache writes (best-effort) | Avoid partial cache files and reduce accidental exposure risk from overly-permissive cache permissions | `src/jwt_workbench/core.py`, `tests/test_jwt_core.py` | `4364bc6` | Medium | trusted
- 2026-02-09 | Add verify-time override (`--at`) in CLI + web verify API/UI | Enable reproducible debugging of exp/nbf/iat behavior without changing system clocks; keep default behavior unchanged when omitted | `src/jwt_workbench/core.py`, `src/jwt_workbench/cli.py`, `src/jwt_workbench/web.py`, `tests/test_jwt_core.py`, `tests/test_web_api.py` | `212a3c0` | High | trusted
- 2026-02-09 | Make decode mode non-validating for time/aud/iss claims | "Decode" should parse JWTs even when expired/not-yet-valid so users can inspect and rely on warnings instead of hard failures | `src/jwt_workbench/core.py`, `tests/test_jwt_core.py` | `212a3c0` | High | trusted
- 2026-02-09 | Add `--jwks-url` fetch with safe cache fallback | Support common OIDC JWKS endpoint workflows while staying offline-first via explicit caching | `src/jwt_workbench/core.py`, `src/jwt_workbench/cli.py`, `tests/test_jwt_core.py` | `7311c86` | Medium | trusted
- 2026-02-09 | Add web UI claims table with human-time rendering | Improve jwt.io parity and reduce friction when reading time-based claims | `src/jwt_workbench/web.py` | `b9d91c9` | Medium | trusted
- 2026-02-09 | Add CSP + anti-embed headers for the local web UI | Reduce accidental data exfil / embedding risk for a local tool with user-controlled input | `src/jwt_workbench/web.py`, `tests/test_web_api.py` | `d726dff` | High | trusted
- 2026-02-09 | Add web UI "Safe export" with signature redaction + optional claim masking | Make it safer to share debugging bundles without leaking full tokens or PII | `src/jwt_workbench/web.py`, `tests/test_web_api.py` | `5aa9dca` | High | trusted
- 2026-02-09 | Expand algorithm coverage (HS/RS/PS/ES variants) with curve-appropriate presets | Meet common JWT ecosystem expectations while preventing key-type confusion and adding compatibility tests | `src/jwt_workbench/web.py`, `src/jwt_workbench/samples.py`, `tests/test_jwt_core.py` | `7e8dadc` | High | trusted
- 2026-02-09 | Add release/version guardrails (`make release-check`) and make CLI `--version` single-source | Avoid drift between `pyproject.toml`, changelog, and CLI output | `scripts/release_check.py`, `src/jwt_workbench/version.py`, `Makefile` | `87f6dab` | Medium | trusted

## Mistakes And Fixes

- 2026-02-09 | Release check regex bug | Root cause: double-escaped regex tokens in a raw string (`\\s`, `\\b`) so the changelog check never matched. Fix: use `\s`/`\b` in the pattern and keep a quick sanity run in `make check`. Prevention: avoid double-escaping in raw regex strings; add a minimal unit-like assertion in scripts when possible. | `scripts/release_check.py` | trusted
- 2026-02-09 | Sample kind regression during refactor | Root cause: `rs256-pem` briefly dropped from the RSA sample-kind branch while expanding variants. Fix: include `rs256-pem` in the RSA path and rely on `make check` to catch breakage. Prevention: add a targeted test ensuring every `SUPPORTED_SAMPLE_KINDS` kind is runnable. | `src/jwt_workbench/samples.py` | trusted
- 2026-02-09 | Web `/api/verify` 500 on PEM private keys | Root cause: verification path passed PEM private keys through to PyJWT/cryptography, which expects a verify-capable public key object; private keys can lack `verify()`. Fix: derive and use the public key for PEM verification (CLI + web) and add regression coverage. Prevention: treat PEM input as "public for verify, private for sign" in loaders; keep an integration test that verifies a token using the sample PEM key material. | `src/jwt_workbench/core.py`, `src/jwt_workbench/web.py`, `tests/test_web_api.py` | trusted

## Verification Evidence

- 2026-02-09 | `make check` | pass
- 2026-02-09 | `./.venv/bin/jwt-workbench validate --token <hs256-sample-token>` | pass (exit 0; `ok=true`)
- 2026-02-09 | `./.venv/bin/jwt-workbench validate --token <hs256-sample-token> --aud wrong` | pass (exit 2; `ok=false` with aud mismatch warning)
- 2026-02-09 | `./.venv/bin/jwt-workbench verify --alg RS256 --key-text -` (stdin: public PEM) | pass (JSON output includes `key_thumbprint_sha256`)
- 2026-02-09 | `./.venv/bin/jwt-workbench verify --alg HS256 --at <exp+1>` | pass (exits 2 with `error: token is expired`)
- 2026-02-09 | `./.venv/bin/jwt-workbench verify --alg HS256 --at <exp-1>` | pass
- 2026-02-09 | `./.venv/bin/jwt-workbench verify --alg RS256 --jwks-url http://127.0.0.1:<port>/jwks --jwks-cache <path> --kid <kid>` | pass (fetch + cache + offline fallback)
- 2026-02-09 | `./.venv/bin/jwt-workbench serve --port 8123` + POST `/api/verify` with `at=<exp+1>` | pass (`token is expired`)
- 2026-02-09 | `./.venv/bin/jwt-workbench serve --port 8123` + `curl http://127.0.0.1:8123/` | pass (HTML served)
- 2026-02-09 | `curl -X POST http://127.0.0.1:8123/api/sample -H 'Content-Type: application/json' -d '{\"kind\":\"hs512\"}'` | pass (returned `HS512` token with 3 segments)
- 2026-02-09 | `curl -X POST http://127.0.0.1:8123/api/export -H 'Content-Type: application/json' -d '{\"token\":\"x.y.z\"}'` | pass (returned JSON error `invalid token format`)
