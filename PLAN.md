# PLAN

JWT Workbench is an offline jwt.io-style CLI + web UI to decode, verify, and sign JWTs (plus key conversion), with practical footgun warnings.

## Shipped

- Decode JWTs without verification (CLI + web).
- Verify HS256/RS256 signatures with local secrets/PEM/JWK/JWKS inputs.
- Optional `aud`/`iss` claim verification + clock-skew `leeway` for verification (CLI + web).
- Web UI: copy buttons (JWT + JWK/JWKS output), keyboard shortcuts, and light/dark theme support.
- Web UI: JSON formatting buttons for header/payload (plus client-side JSON validation before signing).
- Sign HS256/RS256 tokens from JSON payload (CLI + web).
- Convert PEM ↔︎ JWK/JWKS (CLI + web).
- Footgun warnings (`alg=none`, missing/invalid `exp`, expired/near-expiry, missing `aud`/`iss`, `nbf`/`iat` in future, weak HMAC secrets).

## Next

- Web UI: nicer key sections (tabs) + JSON formatting for key/JWK areas.
- Verification: optional allowlist helpers (multiple `aud`/`iss`) and clearer error surfaces for claim mismatches.
- Key UX: JWKS viewer and key picker for multi-key JWKS.

## Top Risks / Unknowns

- Claim verification semantics and user expectations (aud/iss formats, leeway, clock drift).
- Robust handling of malformed tokens and untrusted key inputs.
- Avoiding accidental secret/key leaks (logs, screenshots, clipboard).

## Commands

- Setup: `make setup`
- Quality gate: `make check`
- Run CLI: `python -m jwt_workbench --help`
- Run web UI: `python -m jwt_workbench serve --port 8000`
- More: `PROJECT.md`
