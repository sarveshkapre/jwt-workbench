# JWT Workbench

Offline JWT decode/verify/sign + JWK/JWKS tools with common footgun checks.

## Features

- Decode JWTs without verification.
- Verify signatures for HS256/RS256/ES256/EdDSA.
- Require critical claims during verification (`exp`, `nbf`, `iat`, `aud`, `iss`).
- Sign new JWTs.
- Convert PEM → JWK/JWKS.
- Warn on common claim issues (missing `exp`, expired, missing `aud`/`iss`).
- Export a copy-safe JSON bundle with signature-redacted token for sharing/debugging.

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

Decode from stdin:

```bash
echo "$JWT" | python -m jwt_workbench decode --token -
```

Inspect (decode + warnings):

```bash
python -m jwt_workbench inspect --token "$JWT"
```

Generate a local sample (token + key material):

```bash
python -m jwt_workbench sample --kind hs256
```

Verify (HS256):

```bash
python -m jwt_workbench verify --token "$JWT" --key-text "secret123"
```

Verify with key from stdin:

```bash
python -m jwt_workbench verify --token "$JWT" --alg RS256 --key-text - < public.pem
```

Verify with audience/issuer + clock skew:

```bash
python -m jwt_workbench verify --token "$JWT" --key-text "secret123" --aud "my-aud" --iss "my-iss" --leeway 30
```

Require claims to be present during verification:

```bash
python -m jwt_workbench verify --token "$JWT" --key-text "secret123" --require exp --require aud,iss
```

Verify with multiple audiences:

```bash
python -m jwt_workbench verify --token "$JWT" --key-text "secret123" --aud "aud-1" --aud "aud-2"
```

Verify with multiple issuers:

```bash
python -m jwt_workbench verify --token "$JWT" --key-text "secret123" --iss "iss-1" --iss "iss-2"
```

Verify with a JWKS cache file:

```bash
python -m jwt_workbench verify --token "$JWT" --jwks ./jwks.json --jwks-cache ~/.cache/jwt-workbench/jwks.json --kid my-kid
python -m jwt_workbench verify --token "$JWT" --jwks-cache ~/.cache/jwt-workbench/jwks.json --kid my-kid
```

Export a copy-safe bundle (signature redacted):

```bash
python -m jwt_workbench export --token "$JWT"
```

Sign (HS256):

```bash
python -m jwt_workbench sign --payload '{"sub":"user123","exp":1735689600}' --key-text "secret123"
```

Sign with extra headers:

```bash
python -m jwt_workbench sign --payload '{"sub":"user123"}' --alg none --headers '{"typ":"JWT","foo":"bar"}'
```

Sign (none / unsecured):

```bash
python -m jwt_workbench sign --payload '{"sub":"user123"}' --alg none
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

Verification policy controls (expected `aud`/`iss`, clock skew, and required claims) are available in the web UI verify panel.
