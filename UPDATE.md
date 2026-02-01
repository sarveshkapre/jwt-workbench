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

### Notes

- Per repo workflow, changes are made directly on `main` (no PRs).
