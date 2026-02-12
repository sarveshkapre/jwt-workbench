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

### 2026-02-12T20:01:08Z | Codex execution failure
- Date: 2026-02-12T20:01:08Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-2.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:04:36Z | Codex execution failure
- Date: 2026-02-12T20:04:36Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-3.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:08:04Z | Codex execution failure
- Date: 2026-02-12T20:08:04Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-4.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:11:35Z | Codex execution failure
- Date: 2026-02-12T20:11:35Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-5.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:15:04Z | Codex execution failure
- Date: 2026-02-12T20:15:04Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-6.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:18:36Z | Codex execution failure
- Date: 2026-02-12T20:18:36Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-7.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:22:02Z | Codex execution failure
- Date: 2026-02-12T20:22:02Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-8.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:25:29Z | Codex execution failure
- Date: 2026-02-12T20:25:29Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-9.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:29:07Z | Codex execution failure
- Date: 2026-02-12T20:29:07Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-10.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:32:39Z | Codex execution failure
- Date: 2026-02-12T20:32:39Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-11.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:36:08Z | Codex execution failure
- Date: 2026-02-12T20:36:08Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-12.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:39:34Z | Codex execution failure
- Date: 2026-02-12T20:39:34Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-13.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:43:05Z | Codex execution failure
- Date: 2026-02-12T20:43:05Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-14.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:46:36Z | Codex execution failure
- Date: 2026-02-12T20:46:36Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-15.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:50:06Z | Codex execution failure
- Date: 2026-02-12T20:50:06Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-16.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:53:36Z | Codex execution failure
- Date: 2026-02-12T20:53:36Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-17.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:57:13Z | Codex execution failure
- Date: 2026-02-12T20:57:13Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-18.log
- Commit: pending
- Confidence: medium

### 2026-02-12T21:00:39Z | Codex execution failure
- Date: 2026-02-12T21:00:39Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-19.log
- Commit: pending
- Confidence: medium

### 2026-02-12T21:04:07Z | Codex execution failure
- Date: 2026-02-12T21:04:07Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-20.log
- Commit: pending
- Confidence: medium

### 2026-02-12T21:07:36Z | Codex execution failure
- Date: 2026-02-12T21:07:36Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-21.log
- Commit: pending
- Confidence: medium

### 2026-02-12T21:11:06Z | Codex execution failure
- Date: 2026-02-12T21:11:06Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-22.log
- Commit: pending
- Confidence: medium

### 2026-02-12T21:14:42Z | Codex execution failure
- Date: 2026-02-12T21:14:42Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-23.log
- Commit: pending
- Confidence: medium

### 2026-02-12T21:18:12Z | Codex execution failure
- Date: 2026-02-12T21:18:12Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-24.log
- Commit: pending
- Confidence: medium

### 2026-02-12T21:21:30Z | Codex execution failure
- Date: 2026-02-12T21:21:30Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-jwt-workbench-cycle-25.log
- Commit: pending
- Confidence: medium
