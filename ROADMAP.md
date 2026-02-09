# ROADMAP

## v0.1.0

- Decode, verify, sign, and JWK/JWKS tools with basic footgun checks.
- Optional offline JWKS cache files.
- More claim policy checks (aud/iss allowlists, clock skew).

## Next

- Add import/export support for saved offline workbench sessions (safe defaults: never persist private keys).
- Publish a minimal JSON schema for web API responses and lock it in tests to prevent accidental breaking changes.
- Add `--output text|json` for quicker terminal use.
- Add an opt-in OIDC discovery helper to resolve `jwks_uri` from issuer metadata (network-required; explicit opt-in).
