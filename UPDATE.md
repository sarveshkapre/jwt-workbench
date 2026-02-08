## 2026-02-08

### Summary

- Added required-claims verification policy support for CLI and web API (`exp`, `nbf`, `iat`, `aud`, `iss`).
- Hardened web API request handling with JSON content-type validation, request body size limits, and no-store/security response headers.
- Refactored demo sample/key-preset generation into shared helpers to keep CLI and web behavior aligned.
- Added new integration coverage: web API endpoint tests and an end-to-end local `serve` smoke flow.
- Improved CLI input validation for key-source conflicts and rejected key material for `alg=none` signing.

### How to verify

```bash
make check
python -m jwt_workbench verify --token "$JWT" --key-text "secret123" --require exp --require aud,iss
python -m jwt_workbench serve --port 8000
```

Then open `http://127.0.0.1:8000` and verify with `Required claims` populated.

## 2026-02-03

### Summary

- Fixed the web UI merge conflict and refreshed the layout with key-type tabs and presets.
- Web UI adds a JWKS viewer plus improved key picker for multi-key JWKS.
- Verification now supports issuer allowlists (repeatable/CSV) and clearer claim mismatch errors (CLI + web).
- CLI adds optional offline JWKS cache files for verification workflows.

### How to verify

```bash
make check
python -m jwt_workbench verify --token "$JWT" --key-text "secret123" --iss "iss-1" --iss "iss-2"
python -m jwt_workbench verify --token "$JWT" --jwks ./jwks.json --jwks-cache ~/.cache/jwt-workbench/jwks.json --kid my-kid
python -m jwt_workbench serve --port 8000
```

Then open `http://127.0.0.1:8000` and try the key tabs, presets, and JWKS viewer.

## 2026-02-01

### Summary

- Added optional `aud` / `iss` claim verification and `leeway` (clock skew) support for JWT verification (CLI + web UI).
- Web UI now shows inline status/errors instead of using blocking browser alerts.
- Web UI adds copy-to-clipboard buttons (JWT + JWK/JWKS output), keyboard shortcuts (Ctrl/Cmd+Enter verify, Ctrl/Cmd+Shift+Enter sign), and light/dark theme support.
- Web UI adds JSON format buttons for header/payload and validates JSON before signing.
- Web UI adds JSON formatting for JWK/JWKS key material, and the web API returns consistent JSON errors for JWT failures.
- Web UI adds a JWKS `kid` picker dropdown when a JWKS contains multiple keys.
- Web UI adds a one-click clear button to wipe sensitive fields.
- Web UI adds offline sample presets to load demo tokens/keys quickly.
- CLI adds `inspect` for decode + warnings in one command.
- CLI adds `sample` for generating demo tokens/keys offline.
- Verification supports multiple expected audiences for `aud` (CLI repeatable; web comma-separated).
- CLI now prints clean `error:` messages (and exits non-zero) for invalid tokens/keys instead of stack traces.
- CLI supports `--token -` to read the JWT from stdin (decode/inspect/verify).
- CLI supports `--key-text -` to read key material from stdin (verify/sign).
- CLI supports custom JWT headers when signing (`--headers` / `--headers-file`).
- Added support for generating unsecured `alg=none` tokens (CLI + web UI) without requiring a key.

### How to verify

```bash
make setup
make check
python -m jwt_workbench serve --port 8000
```

Then open `http://127.0.0.1:8000` and try:

- Verify with `Expected aud`, `Expected iss`, and `Clock skew (s)` set.
- Confirm claim mismatches show as an inline error.
- Try copy buttons and keyboard shortcuts.
- Try `Format` for header/payload and confirm invalid JSON is caught before signing.
- Select `none (unsigned)` and confirm `Sign` works with no key.
- Set `Key type` to `JWK` or `JWKS`, paste JSON, and use `Format`.
- Set `Key type` to `JWKS`, paste a multi-key JWKS, and use the `JWKS keys` dropdown to fill `kid`.
- Use `Clear` to wipe token/key fields after working with secrets.
- Use the `Sample preset` picker + `Load` to populate demo tokens/keys entirely offline.
- Try `python -m jwt_workbench inspect --token "$JWT"` to print header/payload + `warnings`.
- Try `python -m jwt_workbench sample --kind rs256-jwks` to generate a token plus a multi-key JWKS (exercise `kid` selection).

### Notes

- Per repo workflow, changes are made directly on `main` (no PRs).
