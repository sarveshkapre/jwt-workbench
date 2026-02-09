# Incidents

This file records reliability/security incidents, root-cause analysis, and prevention rules.

## Template

- Date:
- Summary:
- Impact:
- Detection:
- Root cause:
- Resolution:
- Prevention:
- Evidence:

## 2026-02-09: Web verify 500 on PEM private keys

- Date: 2026-02-09
- Summary: `/api/verify` could return HTTP 500 when given an RSA private key PEM as verification material.
- Impact: Verification requests could fail with an internal server error instead of a clean 4xx or a successful verification (private keys contain public material and are commonly pasted by users).
- Detection: Added integration coverage for key thumbprints exposed the failure (`AttributeError: ... has no attribute 'verify'`).
- Root cause: The verification path passed PEM private keys through to the verification call; cryptography private key objects can lack a `verify()` method, while public keys support verification.
- Resolution: For PEM verification inputs, always derive and use the public key object (CLI + web). Keep thumbprint computed from public JWK fields.
- Prevention: Treat PEM input as "public for verify, private for sign" in loaders; keep an integration test that verifies using sample PEM material.
- Evidence: `src/jwt_workbench/core.py`, `src/jwt_workbench/web.py`, `tests/test_web_api.py` (`4364bc6`).

## 2026-02-09: Transient GitHub 5xx caused flaky pushes and CI checkout failures

- Date: 2026-02-09
- Summary: GitHub intermittently returned 5xx errors during `git push` and GitHub Actions `actions/checkout` fetch.
- Impact: Some pushes required retries; one CI run failed before any repo code executed (checkout never completed).
- Detection: Local `git push` returned 500/502/503; GitHub Actions run logs showed repeated `fatal: unable to access ...: The requested URL returned error: 500` during fetch.
- Root cause: External GitHub service instability (git backend / fetch path).
- Resolution: Add `workflow_dispatch` trigger to CI so the workflow can be re-run manually once GitHub stabilizes.
- Prevention: Keep `workflow_dispatch` enabled; when CI failures occur during checkout/fetch, treat as transient and re-run before investigating code changes.
- Evidence: `.github/workflows/ci.yml` (`2af6d77`); GitHub Actions run `21833618716` failed in `actions/checkout` with HTTP 500.
