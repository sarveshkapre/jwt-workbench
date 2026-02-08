# ROADMAP

## v0.1.0

- Decode, verify, sign, and JWK/JWKS tools with basic footgun checks.
- Optional offline JWKS cache files.
- More claim policy checks (aud/iss allowlists, clock skew).

## Next

- Add ES256/EdDSA verification/signing support with safe key parsing.
- Add JWT export/redaction helpers for safer bug-report sharing.
- Add optional policy profiles (strict/default/legacy) for verification presets.
