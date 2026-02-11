# ROADMAP

## v0.1.0

- Decode, verify, sign, and JWK/JWKS tools with basic footgun checks.
- Optional offline JWKS cache files.
- More claim policy checks (aud/iss allowlists, clock skew).

## Next

- Add pre-verify JWKS fetch/preview in web UI (URL/OIDC) to auto-populate `kid` selection before verification.
- Add `verify --session <file>` to apply saved session context directly in CLI.
