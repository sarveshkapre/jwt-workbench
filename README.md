# JWT Workbench

Offline JWT decode/verify/sign + JWK/JWKS tools with common footgun checks.

## Features

- Decode JWTs without verification.
- Verify signatures for HS256/HS384/HS512, RS256/RS384/RS512, PS256/PS384/PS512, ES256/ES384/ES512, and EdDSA.
- Require critical claims during verification (`exp`, `nbf`, `iat`, `aud`, `iss`).
- Sign new JWTs.
- Convert PEM → JWK/JWKS.
- Warn on common claim issues (missing `exp`, expired, missing `aud`/`iss`).
- Export a copy-safe JSON bundle with signature-redacted token for sharing/debugging.

## Quickstart

```bash
make setup
source .venv/bin/activate
make check
```

## Usage

Decode:

```bash
jwt-workbench decode --token "$JWT"
```

Decode from stdin:

```bash
echo "$JWT" | jwt-workbench decode --token -
```

Inspect (decode + warnings):

```bash
jwt-workbench inspect --token "$JWT"
```

Generate a local sample (token + key material):

```bash
jwt-workbench sample --kind hs256
```

Verify (HS256):

```bash
jwt-workbench verify --token "$JWT" --key-text "secret123"
```

Verify with key from stdin:

```bash
jwt-workbench verify --token "$JWT" --alg RS256 --key-text - < public.pem
```

Verify with audience/issuer + clock skew:

```bash
jwt-workbench verify --token "$JWT" --key-text "secret123" --aud "my-aud" --iss "my-iss" --leeway 30
```

Require claims to be present during verification:

```bash
jwt-workbench verify --token "$JWT" --key-text "secret123" --require exp --require aud,iss
```

Verify with multiple audiences:

```bash
jwt-workbench verify --token "$JWT" --key-text "secret123" --aud "aud-1" --aud "aud-2"
```

Verify with multiple issuers:

```bash
jwt-workbench verify --token "$JWT" --key-text "secret123" --iss "iss-1" --iss "iss-2"
```

Verify with a JWKS cache file:

```bash
jwt-workbench verify --token "$JWT" --jwks ./jwks.json --jwks-cache ~/.cache/jwt-workbench/jwks.json --kid my-kid
jwt-workbench verify --token "$JWT" --jwks-cache ~/.cache/jwt-workbench/jwks.json --kid my-kid
```

Export a copy-safe bundle (signature redacted):

```bash
jwt-workbench export --token "$JWT"
```

Sign (HS256):

```bash
jwt-workbench sign --payload '{"sub":"user123","exp":1735689600}' --key-text "secret123"
```

Sign with extra headers:

```bash
jwt-workbench sign --payload '{"sub":"user123"}' --alg none --headers '{"typ":"JWT","foo":"bar"}'
```

Sign (none / unsecured):

```bash
jwt-workbench sign --payload '{"sub":"user123"}' --alg none
```

Convert PEM → JWK:

```bash
jwt-workbench jwk --pem ./public.pem --kid my-key
```

## Web UI (jwt.io-style)

Launch the local web app:

```bash
jwt-workbench serve --port 8000
```

Then open `http://127.0.0.1:8000` in your browser to decode, verify, sign, and convert keys.

Verification policy controls (expected `aud`/`iss`, clock skew, and required claims) are available in the web UI verify panel.
