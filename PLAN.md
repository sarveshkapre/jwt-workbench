# PLAN.md

## MVP

- Decode JWT without verification.
- Verify HS256/RS256 signatures with key inputs (file/text/JWK/JWKS).
- Sign HS256/RS256 tokens from JSON payload.
- Convert PEM public key → JWK/JWKS.
- Footgun warnings (alg=none, missing exp/aud/iss, expired).

## Non-goals (MVP)

- OIDC discovery or remote key fetching.
- Full JWT policy engine.

## Risks

- Handling malformed tokens; guard with clear errors.
