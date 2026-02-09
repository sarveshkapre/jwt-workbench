# Project Memory

This file captures evolving, structured decisions and evidence for `jwt-workbench`.

## Decisions

### 2026-02-09: Enforce JWK/JWKS key type (`kty`) compatibility with JWT `alg`

- Decision: When loading JWK/JWKS for verification, reject keys whose `kty` doesn't match the selected/inferred `alg` (RSA for `RS*`/`PS*`, EC for `ES*`, OKP for `EdDSA`).
- Why: Prevent common key-confusion mistakes (pasting the wrong JWK/JWKS) from degrading into unclear crypto errors or accidental misuse.
- Evidence: Added `_expected_jwk_kty_for_alg()` and `_jwk_to_key()` and updated JWKS selection logic to safely auto-select a unique matching key by `kty` when `kid` is omitted.
- Commit: `e133712`.
- Confidence: High.
- Trust label: Local implementation + tests.

### 2026-02-09: Add opt-in verification policy profiles (no default behavior change)

- Decision: Introduce `legacy/default/strict` profiles as presets rather than changing defaults.
- Why: JWT ecosystems vary widely; tightening defaults would be a breaking behavior change. Presets give a secure on-ramp without surprising existing workflows.
- Evidence: CLI `--policy` (server-side) and web UI policy picker (client-side, no API schema change).
- Commit: `8f0b9a1`.
- Confidence: High.
- Trust label: Local implementation + tests.

### 2026-02-09: Provide copy-safe export for bug reports by redacting JWT signatures

- Decision: Add `jwt-workbench export` to emit a JSON bundle with `token_redacted` plus decoded header/payload/warnings.
- Why: Teams routinely paste tokens into issues; signature redaction reduces accidental leakage risk while preserving debugging context.
- Evidence: `redact_jws_signature()` + CLI `export` command + smoke tests.
- Commit: `14e0987`.
- Confidence: High.
- Trust label: Local implementation + tests.

