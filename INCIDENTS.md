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
