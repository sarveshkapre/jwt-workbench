# CHANGELOG

## Unreleased

- Web UI: add safe export generator (signature redaction + optional claim masking + one-click copy) for safer bug-report sharing.
- Web API: add `/api/export` and enforce clearer key-type requirements for HS vs non-HS algorithms to prevent key confusion.
- Algorithms: expand supported alg dropdown/presets to include HS384/HS512, RS384/RS512, PS256/PS384/PS512, ES384/ES512 (CLI/web + samples + tests).
- Web: add CSP + anti-embed security headers for the local UI.
- Release: add `make release-check` to validate changelog/version sync and require pinned dependencies.
- Algorithms: add ES256 + EdDSA support for sign/verify across CLI + web, including JWK/JWKS parsing and PEM → JWK conversion for EC/OKP keys.
- Verification: add policy profiles (`legacy`, `default`, `strict`) as presets (CLI `--policy`, web UI picker).
- CLI: add `export` command to emit a copy-safe JSON bundle with signature-redacted token for bug-report sharing.
- Verification: add required-claims policy support (`--require` / web `require`) for `exp`, `nbf`, `iat`, `aud`, and `iss`.
- CLI: enforce clearer key-source validation (mutually exclusive key inputs for verify/sign, and reject key material for `alg=none`).
- Web API: add request hardening (JSON content-type enforcement, request body size cap, incomplete body checks) and no-store response headers.
- Refactor: move sample/key-preset generation into shared helpers used by CLI and web paths.
- Tests: add dedicated web API integration tests and a real `serve` smoke flow.
- Web UI: key-type tabs, key presets, and a JWKS viewer.
- Verification: issuer allowlists (repeatable/CSV) and clearer claim mismatch errors.
- CLI: optional offline JWKS cache file support.
- Add optional `aud`/`iss` verification and `leeway` (clock skew) to JWT verification (CLI + web).
- Web UI: copy-to-clipboard buttons, keyboard shortcuts, and light/dark theme support.
- Web UI: JSON format buttons for header/payload and client-side JSON validation before signing.
- Web UI: JSON format button for JWK/JWKS key material.
- Web API: return JSON errors for PyJWT failures and unexpected exceptions.
- Web UI: JWKS `kid` picker when multiple keys are present.
- Web UI: clear button to wipe token/key fields.
- Web UI: sample presets to load demo tokens/keys offline.
- CLI: add `inspect` command to decode and include warnings in output.
- CLI: add `sample` command to generate demo tokens/keys offline.
- Verification: allow multiple expected audiences for `aud` (CLI + web).
- CLI: handle invalid tokens/keys with clean `error:` messages and non-zero exit codes (no tracebacks).
- CLI: allow `--token -` to read JWTs from stdin (decode/inspect/verify).
- CLI: allow `--key-text -` to read key material from stdin (verify/sign).
- CLI: allow setting custom JWT headers when signing (`--headers` / `--headers-file`).
- Support generating unsecured `alg=none` tokens (CLI + web) without requiring key material.

## v0.1.0 - 2026-01-31

- Decode JWTs without verification.
- Verify HS256/RS256 signatures with local keys/JWK/JWKS.
- Sign JWTs from JSON payload.
- Convert PEM public keys to JWK/JWKS.
- Footgun warnings for common claim issues.
