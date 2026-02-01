# CHANGELOG

## Unreleased

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
- Support generating unsecured `alg=none` tokens (CLI + web) without requiring key material.

## v0.1.0 - 2026-01-31

- Decode JWTs without verification.
- Verify HS256/RS256 signatures with local keys/JWK/JWKS.
- Sign JWTs from JSON payload.
- Convert PEM public keys to JWK/JWKS.
- Footgun warnings for common claim issues.
