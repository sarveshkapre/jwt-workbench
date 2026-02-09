from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from jwt import exceptions as jwt_exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from jwt_workbench.core import (
    decode_token,
    jwk_from_pem,
    jwks_from_pem,
    load_key_from_material,
    redact_jws_signature,
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


def test_none_sign_decode() -> None:
    payload = {"sub": "no-sig", "exp": int(time.time()) + 60}
    token = sign_token(payload, key_path=None, key_text=None, alg="none", kid=None)
    header, decoded = decode_token(token)
    assert header["alg"] == "none"
    assert decoded["sub"] == "no-sig"
