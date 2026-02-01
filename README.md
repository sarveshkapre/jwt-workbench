# JWT Workbench

Offline JWT decode/verify/sign + JWK/JWKS tools with common footgun checks.

## Features

- Decode JWTs without verification.
- Verify signatures for HS256/RS256.
- Sign new JWTs.
- Convert PEM → JWK/JWKS.
- Warn on common claim issues (missing `exp`, expired, missing `aud`/`iss`).

## Quickstart

```bash
make setup
make check
```

## Usage

Decode:

```bash
python -m jwt_workbench decode --token "$JWT"
```

Verify (HS256):

```bash
python -m jwt_workbench verify --token "$JWT" --key-text "secret123"
```

Sign (HS256):

```bash
python -m jwt_workbench sign --payload '{"sub":"user123","exp":1735689600}' --key-text "secret123"
```

Convert PEM → JWK:

```bash
python -m jwt_workbench jwk --pem ./public.pem --kid my-key
```

## Web UI (jwt.io-style)

Launch the local web app:

```bash
python -m jwt_workbench serve --port 8000
```

Then open `http://127.0.0.1:8000` in your browser to decode, verify, sign, and convert keys.
