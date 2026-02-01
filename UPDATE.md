## 2026-02-01

### Summary

- Added optional `aud` / `iss` claim verification and `leeway` (clock skew) support for JWT verification (CLI + web UI).
- Web UI now shows inline status/errors instead of using blocking browser alerts.
- Web UI adds copy-to-clipboard buttons (JWT + JWK/JWKS output), keyboard shortcuts (Ctrl/Cmd+Enter verify, Ctrl/Cmd+Shift+Enter sign), and light/dark theme support.

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

### Notes

- Per repo workflow, changes are made directly on `main` (no PRs).
