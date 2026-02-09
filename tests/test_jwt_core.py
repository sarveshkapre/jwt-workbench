from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest
from jwt import exceptions as jwt_exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from jwt_workbench.core import (
    analyze_claims,
    decode_token,
    discover_jwks_uri_from_oidc_issuer,
    format_jwt_error,
    jwk_from_pem,
    jwk_thumbprint_sha256,
    jwks_from_pem,
    load_key_from_material,
    redact_jws_signature,
    sign_token,
    verify_token,
    verify_token_with_key,
)
from jwt_workbench.samples import SUPPORTED_SAMPLE_KINDS, generate_sample


def _rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def _ec_p256_keypair() -> tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def _ec_p384_keypair() -> tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP384R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def _ec_p521_keypair() -> tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP521R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def _ed25519_keypair() -> tuple[str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def test_hs256_sign_verify_decode() -> None:
    payload = {"sub": "user123", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text="secret123", alg="HS256", kid=None)

    header, decoded = decode_token(token)
    assert header["alg"] == "HS256"
    assert decoded["sub"] == "user123"

    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text="secret123",
        jwk_path=None,
        jwks_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == "HS256"
    assert verified["sub"] == "user123"


def test_decode_does_not_validate_exp() -> None:
    now = int(time.time())
    token = sign_token(
        {"sub": "expired-user", "exp": now - 10},
        key_path=None,
        key_text="secret123",
        alg="HS256",
        kid=None,
    )
    header, decoded = decode_token(token)
    assert header["alg"] == "HS256"
    assert decoded["sub"] == "expired-user"


def test_analyze_claims_warns_on_risky_headers() -> None:
    # Keep claim warnings out of the way so this test is stable.
    payload = {"exp": 2000000100, "aud": "a", "iss": "i"}
    header = {
        "alg": "RS256",
        "jku": "https://issuer.example/.well-known/jwks.json",
        "x5u": "https://issuer.example/certs.pem",
        "crit": ["b64"],
    }
    warnings = analyze_claims(payload, header, now=2000000000)
    assert "token header contains jku (some stacks may fetch keys over the network)" in warnings
    assert "token header contains x5u (some stacks may fetch certs over the network)" in warnings
    assert "token header contains crit (requires special processing)" in warnings


def test_format_jwt_error_iat_nbf_and_time_claim_integer_errors() -> None:
    assert (
        format_jwt_error(jwt_exceptions.ImmatureSignatureError("The token is not yet valid (iat)"))
        == "iat is in the future"
    )
    assert (
        format_jwt_error(jwt_exceptions.ImmatureSignatureError("The token is not yet valid (nbf)"))
        == "token is not valid yet (nbf in the future)"
    )
    assert (
        format_jwt_error(
            jwt_exceptions.InvalidIssuedAtError("Issued At claim (iat) must be an integer.")
        )
        == "iat claim is not an integer"
    )
    assert (
        format_jwt_error(
            jwt_exceptions.DecodeError("Expiration Time claim (exp) must be an integer.")
        )
        == "exp claim is not an integer"
    )
    assert (
        format_jwt_error(jwt_exceptions.DecodeError("Not Before claim (nbf) must be an integer."))
        == "nbf claim is not an integer"
    )


@pytest.mark.parametrize("alg", ["HS384", "HS512"])
def test_hs_variants_sign_verify_decode(alg: str) -> None:
    payload = {"sub": "user123", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text="secret123", alg=alg, kid=None)

    header, decoded = decode_token(token)
    assert header["alg"] == alg
    assert decoded["sub"] == "user123"

    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text="secret123",
        jwk_path=None,
        jwks_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == alg
    assert verified["sub"] == "user123"


@pytest.mark.parametrize("alg", ["RS384", "RS512", "PS256", "PS384", "PS512"])
def test_rsa_variants_sign_verify(alg: str) -> None:
    private_pem, public_pem = _rsa_keypair()
    payload = {"aud": "test", "exp": int(time.time()) + 60}

    token = sign_token(payload, key_path=None, key_text=private_pem, alg=alg, kid="k1")
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=public_pem,
        jwk_path=None,
        jwks_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == alg
    assert verified["aud"] == "test"


def test_es384_sign_verify() -> None:
    private_pem, public_pem = _ec_p384_keypair()
    payload = {"aud": "test", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text=private_pem, alg="ES384", kid="ec384")
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=public_pem,
        jwk_path=None,
        jwks_path=None,
        jwks_cache_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == "ES384"
    assert verified["aud"] == "test"


def test_es512_sign_verify() -> None:
    private_pem, public_pem = _ec_p521_keypair()
    payload = {"aud": "test", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text=private_pem, alg="ES512", kid="ec521")
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=public_pem,
        jwk_path=None,
        jwks_path=None,
        jwks_cache_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == "ES512"
    assert verified["aud"] == "test"


@pytest.mark.parametrize("kind", sorted(SUPPORTED_SAMPLE_KINDS))
def test_generate_sample_kinds(kind: str) -> None:
    sample = generate_sample(kind)
    assert sample["kind"] == kind
    assert isinstance(sample["token"], str) and sample["token"]
    assert isinstance(sample["alg"], str) and sample["alg"]
    assert isinstance(sample["header"], dict)
    assert isinstance(sample["payload"], dict)
    # JWS tokens should always have 3 dot-separated segments (including alg=none).
    assert len(sample["token"].split(".")) == 3


def test_rs256_sign_verify_and_jwk() -> None:
    private_pem, public_pem = _rsa_keypair()
    payload = {"aud": "test", "exp": int(time.time()) + 60}

    token = sign_token(payload, key_path=None, key_text=private_pem, alg="RS256", kid="k1")
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=public_pem,
        jwk_path=None,
        jwks_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == "RS256"
    assert verified["aud"] == "test"

    jwk = jwk_from_pem(public_pem, kid="k1")
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == "k1"

    jwks = jwks_from_pem(public_pem, kid="k1")
    assert "keys" in jwks
    assert jwks["keys"][0]["kty"] == "RSA"


def test_es256_sign_verify_and_jwk_and_jwks_autoselect(tmp_path: Path) -> None:
    private_pem, public_pem = _ec_p256_keypair()
    payload = {"aud": "test", "exp": int(time.time()) + 60}

    token = sign_token(payload, key_path=None, key_text=private_pem, alg="ES256", kid="ec1")
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=public_pem,
        jwk_path=None,
        jwks_path=None,
        jwks_cache_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == "ES256"
    assert verified["aud"] == "test"

    jwk = jwk_from_pem(public_pem, kid="ec1")
    assert jwk["kty"] == "EC"
    assert jwk["kid"] == "ec1"

    # JWKS autoselects the only key with matching kty when kid is omitted.
    rsa_private, rsa_public = _rsa_keypair()
    rsa_jwk = jwk_from_pem(rsa_public, kid="rsa1")
    jwks_path = tmp_path / "jwks-mixed.json"
    jwks_path.write_text(json.dumps({"keys": [rsa_jwk, jwk]}, indent=2, sort_keys=True), "utf-8")
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=None,
        jwk_path=None,
        jwks_path=str(jwks_path),
        jwks_cache_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == "ES256"
    assert verified["aud"] == "test"

    # Ensure RSA key still works for RS256 (sanity check the mixed JWKS keys are valid).
    rsa_token = sign_token(payload, key_path=None, key_text=rsa_private, alg="RS256", kid="rsa1")
    header, verified = verify_token(
        token=rsa_token,
        key_path=None,
        key_text=rsa_public,
        jwk_path=None,
        jwks_path=None,
        jwks_cache_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == "RS256"
    assert verified["aud"] == "test"


def test_eddsa_sign_verify_and_jwk() -> None:
    private_pem, public_pem = _ed25519_keypair()
    payload = {"aud": "test", "exp": int(time.time()) + 60}

    token = sign_token(payload, key_path=None, key_text=private_pem, alg="EdDSA", kid="ed1")
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=public_pem,
        jwk_path=None,
        jwks_path=None,
        jwks_cache_path=None,
        kid=None,
        alg=None,
    )
    assert header["alg"] == "EdDSA"
    assert verified["aud"] == "test"

    jwk = jwk_from_pem(public_pem, kid="ed1")
    assert jwk["kty"] == "OKP"
    assert jwk["kid"] == "ed1"


def test_rfc7638_thumbprint_example() -> None:
    # RFC 7638 Appendix A.1 (RSA) example thumbprint.
    jwk = {
        "kty": "RSA",
        "n": (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z"
            "wu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsG"
            "Y4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAt"
            "aSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFT"
            "WhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-"
            "kEgU8awapJzKnqDKgw"
        ),
        "e": "AQAB",
    }
    assert jwk_thumbprint_sha256(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_refuses_algorithm_kty_mismatch_for_jwk(tmp_path: Path) -> None:
    ec_private, ec_public = _ec_p256_keypair()

    rsa_private, _ = _rsa_keypair()
    rsa_token = sign_token(
        {"exp": int(time.time()) + 60}, key_path=None, key_text=rsa_private, alg="RS256", kid=None
    )

    ec_jwk_path = tmp_path / "ec.jwk.json"
    ec_jwk_path.write_text(json.dumps(jwk_from_pem(ec_public), indent=2, sort_keys=True), "utf-8")
    with pytest.raises(ValueError, match="does not match algorithm"):
        verify_token(
            token=rsa_token,
            key_path=None,
            key_text=None,
            jwk_path=str(ec_jwk_path),
            jwks_path=None,
            jwks_cache_path=None,
            kid=None,
            alg=None,
        )


def test_redact_jws_signature() -> None:
    token = sign_token(
        {"sub": "x", "exp": int(time.time()) + 60},
        key_path=None,
        key_text="secret123",
        alg="HS256",
        kid=None,
    )
    redacted = redact_jws_signature(token)
    parts = token.split(".")
    redacted_parts = redacted.split(".")
    assert len(parts) == 3
    assert len(redacted_parts) == 3
    assert redacted_parts[0] == parts[0]
    assert redacted_parts[1] == parts[1]
    assert redacted_parts[2] == "REDACTED"

    with pytest.raises(ValueError):
        redact_jws_signature("x.y")


def test_hs_refuses_pem_secret() -> None:
    private_pem, _ = _rsa_keypair()
    payload = {"exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text="secret123", alg="HS256", kid=None)

    with pytest.raises(ValueError):
        verify_token(
            token=token,
            key_path=None,
            key_text=private_pem,
            jwk_path=None,
            jwks_path=None,
            kid=None,
            alg="HS256",
        )


def test_verify_with_loaded_key_material() -> None:
    payload = {"sub": "site-user", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text="secret123", alg="HS256", kid=None)
    key = load_key_from_material("secret123", alg="HS256", kind="secret")
    header, decoded = verify_token_with_key(token, key=key, alg="HS256")
    assert header["alg"] == "HS256"
    assert decoded["sub"] == "site-user"


def test_verify_aud_iss_with_leeway() -> None:
    now = int(time.time())
    payload = {"aud": "my-aud", "iss": "my-iss", "exp": now - 2}
    token = sign_token(payload, key_path=None, key_text="secret123", alg="HS256", kid=None)

    # Without leeway, exp verification should fail.
    with pytest.raises(jwt_exceptions.ExpiredSignatureError):
        verify_token(
            token=token,
            key_path=None,
            key_text="secret123",
            jwk_path=None,
            jwks_path=None,
            kid=None,
            alg="HS256",
            audience="my-aud",
            issuer="my-iss",
            leeway=0,
        )

    # With leeway, exp can pass; aud/iss must match.
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text="secret123",
        jwk_path=None,
        jwks_path=None,
        kid=None,
        alg="HS256",
        audience="my-aud",
        issuer="my-iss",
        leeway=5,
    )
    assert header["alg"] == "HS256"
    assert verified["aud"] == "my-aud"
    assert verified["iss"] == "my-iss"

    with pytest.raises(jwt_exceptions.InvalidAudienceError):
        verify_token(
            token=token,
            key_path=None,
            key_text="secret123",
            jwk_path=None,
            jwks_path=None,
            kid=None,
            alg="HS256",
            audience="wrong-aud",
            issuer="my-iss",
            leeway=5,
        )


def test_verify_at_overrides_time_claims_and_leeway() -> None:
    now = int(time.time())
    token = sign_token(
        {"sub": "x", "exp": now + 30},
        key_path=None,
        key_text="secret123",
        alg="HS256",
        kid=None,
    )

    with pytest.raises(jwt_exceptions.ExpiredSignatureError):
        verify_token(
            token=token,
            key_path=None,
            key_text="secret123",
            jwk_path=None,
            jwks_path=None,
            jwks_cache_path=None,
            kid=None,
            alg="HS256",
            audience=None,
            issuer=None,
            leeway=0,
            at=now + 31,
        )

    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text="secret123",
        jwk_path=None,
        jwks_path=None,
        jwks_cache_path=None,
        kid=None,
        alg="HS256",
        audience=None,
        issuer=None,
        leeway=10,
        at=now + 31,
    )
    assert header["alg"] == "HS256"
    assert verified["sub"] == "x"


def test_verify_at_formats_iat_and_nbf_errors() -> None:
    now = int(time.time())
    token_iat = sign_token(
        {"exp": now + 120, "iat": now + 60},
        key_path=None,
        key_text="secret123",
        alg="HS256",
        kid=None,
    )
    with pytest.raises(jwt_exceptions.PyJWTError) as excinfo:
        verify_token(
            token=token_iat,
            key_path=None,
            key_text="secret123",
            jwk_path=None,
            jwks_path=None,
            jwks_cache_path=None,
            kid=None,
            alg="HS256",
            audience=None,
            issuer=None,
            leeway=0,
            at=now,
        )
    assert format_jwt_error(excinfo.value) == "iat is in the future"

    token_nbf = sign_token(
        {"exp": now + 120, "nbf": now + 60},
        key_path=None,
        key_text="secret123",
        alg="HS256",
        kid=None,
    )
    with pytest.raises(jwt_exceptions.PyJWTError) as excinfo:
        verify_token(
            token=token_nbf,
            key_path=None,
            key_text="secret123",
            jwk_path=None,
            jwks_path=None,
            jwks_cache_path=None,
            kid=None,
            alg="HS256",
            audience=None,
            issuer=None,
            leeway=0,
            at=now,
        )
    assert format_jwt_error(excinfo.value) == "token is not valid yet (nbf in the future)"


def test_verify_at_handles_null_time_claim_types() -> None:
    now = int(time.time())
    token = sign_token(
        {"exp": None},
        key_path=None,
        key_text="secret123",
        alg="HS256",
        kid=None,
    )
    with pytest.raises(jwt_exceptions.PyJWTError) as excinfo:
        verify_token(
            token=token,
            key_path=None,
            key_text="secret123",
            jwk_path=None,
            jwks_path=None,
            jwks_cache_path=None,
            kid=None,
            alg="HS256",
            audience=None,
            issuer=None,
            leeway=0,
            at=now,
        )
    assert format_jwt_error(excinfo.value) == "exp claim is not an integer"


def test_verify_audience_allowlist() -> None:
    payload = {"aud": "a1", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text="secret123", alg="HS256", kid=None)
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text="secret123",
        jwk_path=None,
        jwks_path=None,
        kid=None,
        alg="HS256",
        audience=["a2", "a1"],
        issuer=None,
        leeway=0,
    )
    assert header["alg"] == "HS256"
    assert verified["aud"] == "a1"


def test_verify_issuer_allowlist() -> None:
    now = int(time.time())
    payload = {"iss": "issuer-b", "exp": now + 60}
    token = sign_token(payload, key_path=None, key_text="secret123", alg="HS256", kid=None)
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text="secret123",
        jwk_path=None,
        jwks_path=None,
        jwks_cache_path=None,
        kid=None,
        alg="HS256",
        audience=None,
        issuer=["issuer-a", "issuer-b"],
        leeway=0,
    )
    assert header["alg"] == "HS256"
    assert verified["iss"] == "issuer-b"

    with pytest.raises(jwt_exceptions.InvalidIssuerError):
        verify_token(
            token=token,
            key_path=None,
            key_text="secret123",
            jwk_path=None,
            jwks_path=None,
            jwks_cache_path=None,
            kid=None,
            alg="HS256",
            audience=None,
            issuer=["issuer-a"],
            leeway=0,
        )


def test_verify_required_claims() -> None:
    payload = {"sub": "required-user", "aud": "required-aud", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text="secret123", alg="HS256", kid=None)
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text="secret123",
        jwk_path=None,
        jwks_path=None,
        jwks_cache_path=None,
        kid=None,
        alg="HS256",
        audience=None,
        issuer=None,
        leeway=0,
        required_claims=["exp", "aud"],
    )
    assert header["alg"] == "HS256"
    assert verified["aud"] == "required-aud"

    with pytest.raises(jwt_exceptions.MissingRequiredClaimError):
        verify_token(
            token=token,
            key_path=None,
            key_text="secret123",
            jwk_path=None,
            jwks_path=None,
            jwks_cache_path=None,
            kid=None,
            alg="HS256",
            audience=None,
            issuer=None,
            leeway=0,
            required_claims=["iss"],
        )


def test_verify_invalid_required_claim_name() -> None:
    payload = {"sub": "required-user", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text="secret123", alg="HS256", kid=None)
    with pytest.raises(ValueError):
        verify_token(
            token=token,
            key_path=None,
            key_text="secret123",
            jwk_path=None,
            jwks_path=None,
            jwks_cache_path=None,
            kid=None,
            alg="HS256",
            audience=None,
            issuer=None,
            leeway=0,
            required_claims=["sub"],
        )


def test_jwks_cache_file(tmp_path: Path) -> None:
    private_pem, public_pem = _rsa_keypair()
    payload = {"sub": "cache-user", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text=private_pem, alg="RS256", kid="cache-k1")

    jwk = jwk_from_pem(public_pem, kid="cache-k1")
    jwks = {"keys": [jwk]}
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(json.dumps(jwks), encoding="utf-8")
    cache_path = tmp_path / "cache" / "jwks-cache.json"

    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=None,
        jwk_path=None,
        jwks_path=str(jwks_path),
        jwks_cache_path=str(cache_path),
        kid="cache-k1",
        alg="RS256",
        audience=None,
        issuer=None,
        leeway=0,
    )
    assert header["alg"] == "RS256"
    assert verified["sub"] == "cache-user"
    assert cache_path.exists()
    assert not any(path.suffix == ".tmp" for path in cache_path.parent.iterdir())
    assert (cache_path.stat().st_mode & 0o777) == 0o600

    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=None,
        jwk_path=None,
        jwks_path=None,
        jwks_cache_path=str(cache_path),
        kid="cache-k1",
        alg="RS256",
        audience=None,
        issuer=None,
        leeway=0,
    )
    assert header["alg"] == "RS256"
    assert verified["sub"] == "cache-user"


def test_jwks_url_fetch_and_cache_fallback(tmp_path: Path) -> None:
    private_pem, public_pem = _rsa_keypair()
    token = sign_token(
        {"sub": "url-user", "exp": int(time.time()) + 60},
        key_path=None,
        key_text=private_pem,
        alg="RS256",
        kid="url-k1",
    )
    jwks = {"keys": [jwk_from_pem(public_pem, kid="url-k1")]}
    cache_path = tmp_path / "jwks-cache.json"

    class JWKSHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http handler API
            body = json.dumps(jwks).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _fmt: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), JWKSHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    host_text = host.decode("ascii") if isinstance(host, bytes) else host
    url = f"http://{host_text}:{port}/jwks"
    try:
        header, verified = verify_token(
            token=token,
            key_path=None,
            key_text=None,
            jwk_path=None,
            jwks_path=None,
            jwks_url=url,
            jwks_cache_path=str(cache_path),
            kid="url-k1",
            alg="RS256",
            audience=None,
            issuer=None,
            leeway=0,
        )
        assert header["alg"] == "RS256"
        assert verified["sub"] == "url-user"
        assert cache_path.exists()
        assert not any(path.suffix == ".tmp" for path in cache_path.parent.iterdir())
        assert (cache_path.stat().st_mode & 0o777) == 0o600
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    # Offline: verify using the cache if the JWKS fetch fails.
    header, verified = verify_token(
        token=token,
        key_path=None,
        key_text=None,
        jwk_path=None,
        jwks_path=None,
        jwks_url=url,
        jwks_cache_path=str(cache_path),
        kid="url-k1",
        alg="RS256",
        audience=None,
        issuer=None,
        leeway=0,
    )
    assert header["alg"] == "RS256"
    assert verified["sub"] == "url-user"


def test_oidc_discovery_resolves_jwks_uri(tmp_path: Path) -> None:
    private_pem, public_pem = _rsa_keypair()
    token = sign_token(
        {"sub": "oidc-user", "exp": int(time.time()) + 60},
        key_path=None,
        key_text=private_pem,
        alg="RS256",
        kid="oidc-k1",
    )
    jwks = {"keys": [jwk_from_pem(public_pem, kid="oidc-k1")]}
    cache_path = tmp_path / "jwks-cache.json"

    class OIDCHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http handler API
            host, port = cast(tuple[str | bytes, int], self.server.server_address)
            host_text = host.decode("ascii") if isinstance(host, bytes) else host
            if self.path == "/issuer/.well-known/openid-configuration":
                body = json.dumps({"jwks_uri": f"http://{host_text}:{port}/jwks"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/jwks":
                body = json.dumps(jwks).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, _fmt: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), OIDCHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = cast(tuple[str | bytes, int], server.server_address)
    host_text = host.decode("ascii") if isinstance(host, bytes) else host
    issuer_url = f"http://{host_text}:{port}/issuer/"
    try:
        jwks_uri = discover_jwks_uri_from_oidc_issuer(issuer_url)
        assert jwks_uri.endswith("/jwks")
        header, verified = verify_token(
            token=token,
            key_path=None,
            key_text=None,
            jwk_path=None,
            jwks_path=None,
            jwks_url=jwks_uri,
            jwks_cache_path=str(cache_path),
            kid="oidc-k1",
            alg="RS256",
            audience=None,
            issuer=None,
            leeway=0,
        )
        assert header["alg"] == "RS256"
        assert verified["sub"] == "oidc-user"
        assert cache_path.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_none_sign_decode() -> None:
    payload = {"sub": "no-sig", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text=None, alg="none", kid=None)
    header, decoded = decode_token(token)
    assert header["alg"] == "none"
    assert decoded["sub"] == "no-sig"
