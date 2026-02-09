# ROADMAP

## v0.1.0

- Decode, verify, sign, and JWK/JWKS tools with basic footgun checks.
- Optional offline JWKS cache files.
- More claim policy checks (aud/iss allowlists, clock skew).

## Next

- Add web UI export/redaction helpers for safer bug-report sharing (payload claim masking + one-click copy).
- Expand algorithm coverage beyond the defaults (HS/RS/ES variants) with compatibility tests.
- Add release automation checks for changelog/version sync and dependency pin drift.
