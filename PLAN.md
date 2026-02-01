# PLAN

JWT Workbench is an offline jwt.io-style CLI + web UI to decode, verify, and sign JWTs (plus key conversion), with practical footgun warnings.

## Shipped

- Decode JWTs without verification (CLI + web).
- CLI: `inspect` command to decode and emit warnings (json includes `warnings`).
- Verify HS256/RS256 signatures with local secrets/PEM/JWK/JWKS inputs.
- Optional `aud`/`iss` claim verification + clock-skew `leeway` for verification (CLI + web).
- Verification: support multiple expected `aud` values (CLI repeatable; web comma-separated).
- Web UI: copy buttons (JWT + JWK/JWKS output), keyboard shortcuts, and light/dark theme support.
- Web UI: JSON formatting buttons for header/payload (plus client-side JSON validation before signing).
- Web UI: JSON formatting button for JWK/JWKS key material.
- Web API: more robust error handling (PyJWT errors returned as JSON 400; unexpected errors as JSON 500).
- Web UI: JWKS key picker (dropdown) for selecting `kid` when a JWKS has multiple keys.
- Web UI: one-click clear to wipe sensitive fields.
- Web UI: sample presets (HS256 / RS256 / JWKS / none) for quick offline demos.
- CLI: `sample` command to generate offline demo tokens/keys.
- Signing: support generating unsecured `alg=none` tokens (CLI + web), without requiring key material.
- Sign HS256/RS256 tokens from JSON payload (CLI + web).
- Convert PEM ↔︎ JWK/JWKS (CLI + web).
- CLI: clean error messages and exit codes (no tracebacks) for invalid tokens/keys.
- CLI: accept tokens from stdin via `--token -`.
- CLI: accept key material from stdin via `--key-text -`.
- Footgun warnings (`alg=none`, missing/invalid `exp`, expired/near-expiry, missing `aud`/`iss`, `nbf`/`iat` in future, weak HMAC secrets).

## Next

- Web UI: nicer key sections (tabs) + key material presets.
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
