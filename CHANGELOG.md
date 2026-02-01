# CHANGELOG

## Unreleased

- Add optional `aud`/`iss` verification and `leeway` (clock skew) to JWT verification (CLI + web).
- Web UI: copy-to-clipboard buttons, keyboard shortcuts, and light/dark theme support.
- Web UI: JSON format buttons for header/payload and client-side JSON validation before signing.

## v0.1.0 - 2026-01-31

- Decode JWTs without verification.
- Verify HS256/RS256 signatures with local keys/JWK/JWKS.
- Sign JWTs from JSON payload.
- Convert PEM public keys to JWK/JWKS.
- Footgun warnings for common claim issues.
