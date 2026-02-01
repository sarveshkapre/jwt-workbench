from __future__ import annotations

import time

import pytest
from jwt import exceptions as jwt_exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from jwt_workbench.core import (
    decode_token,
    jwk_from_pem,
    jwks_from_pem,
    load_key_from_material,
    sign_token,
    verify_token_with_key,
    verify_token,
)


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
