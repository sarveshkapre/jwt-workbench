from __future__ import annotations

import json
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from .core import analyze_claims, decode_token, jwk_from_pem, sign_token

SUPPORTED_SAMPLE_KINDS = frozenset(
    {
        "hs256",
        "hs384",
        "hs512",
        "rs256-pem",
        "rs384-pem",
        "rs512-pem",
        "ps256-pem",
        "ps384-pem",
        "ps512-pem",
        "rs256-jwks",
        "es256-pem",
        "es384-pem",
        "es512-pem",
        "eddsa-pem",
        "none",
    }
)
SUPPORTED_KEY_PRESET_KINDS = frozenset(
    {
        "pem-private",
        "pem-public",
        "pem-ec-private",
        "pem-ec-public",
        "pem-ec-p384-private",
        "pem-ec-p384-public",
        "pem-ec-p521-private",
        "pem-ec-p521-public",
        "pem-ed25519-private",
        "pem-ed25519-public",
        "jwk",
        "jwk-ec",
        "jwk-ec-p384",
        "jwk-ec-p521",
        "jwk-okp",
        "jwks",
        "jwks-ec",
        "jwks-ec-p384",
        "jwks-ec-p521",
        "jwks-okp",
    }
)
DEFAULT_REQUIRED_CLAIMS = ["exp", "aud", "iss"]
DEFAULT_POLICY = {
    "aud": "demo-aud",
    "iss": "demo-iss",
    "leeway": 30,
    "require": DEFAULT_REQUIRED_CLAIMS,
}


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


def _ec_keypair(curve: ec.EllipticCurve) -> tuple[str, str]:
    private_key = ec.generate_private_key(curve)
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
    return _ec_keypair(ec.SECP256R1())


def _ec_p384_keypair() -> tuple[str, str]:
    return _ec_keypair(ec.SECP384R1())


def _ec_p521_keypair() -> tuple[str, str]:
    return _ec_keypair(ec.SECP521R1())


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


def _sample_payload(exp_seconds: int) -> dict[str, Any]:
    now = int(time.time())
    return {
        "sub": "demo-user",
        "aud": "demo-aud",
        "iss": "demo-iss",
        "iat": now,
        "exp": now + int(exp_seconds),
    }


def generate_sample(kind: str, exp_seconds: int = 3600) -> dict[str, Any]:
    if kind not in SUPPORTED_SAMPLE_KINDS:
        raise ValueError("unknown sample kind")

    payload = _sample_payload(exp_seconds)
    if kind == "none":
        token = sign_token(payload, key_path=None, key_text=None, alg="none", kid=None)
        header, decoded = decode_token(token)
        return {
            "kind": kind,
            "alg": "none",
            "token": token,
            "header": header,
            "payload": decoded,
            "warnings": analyze_claims(decoded, header),
            "key_type": "secret",
            "key_text": "",
            "kid": "",
            **DEFAULT_POLICY,
        }

    if kind in {"hs256", "hs384", "hs512"}:
        secret = "demo-secret-please-change"
        alg = kind.upper()
        token = sign_token(payload, key_path=None, key_text=secret, alg=alg, kid=None)
        header, decoded = decode_token(token)
        return {
            "kind": kind,
            "alg": alg,
            "token": token,
            "header": header,
            "payload": decoded,
            "warnings": analyze_claims(decoded, header, hmac_key_len=len(secret.encode("utf-8"))),
            "verify_key": {"key_type": "secret", "key_text": secret},
            "key_type": "secret",
            "key_text": secret,
            "kid": "",
            **DEFAULT_POLICY,
        }

    if kind in {
        "rs256-pem",
        "rs384-pem",
        "rs512-pem",
        "ps256-pem",
        "ps384-pem",
        "ps512-pem",
        "rs256-jwks",
    }:
        private_pem, public_pem = _rsa_keypair()
        alg = kind.split("-", 1)[0].upper()
        token = sign_token(payload, key_path=None, key_text=private_pem, alg=alg, kid="demo-k1")
        header, decoded = decode_token(token)
        base: dict[str, Any] = {
            "kind": kind,
            "alg": alg,
            "token": token,
            "header": header,
            "payload": decoded,
            "warnings": analyze_claims(decoded, header),
            "kid": "demo-k1",
            "verify_key": {"key_type": "pem", "key_text": public_pem},
            "sign_key": {"key_type": "pem", "key_text": private_pem},
            **DEFAULT_POLICY,
        }
        if kind != "rs256-jwks":
            base["key_type"] = "pem"
            base["key_text"] = private_pem
            return base

        jwk1 = jwk_from_pem(public_pem, kid="demo-k1")
        _, other_public_pem = _rsa_keypair()
        jwk2 = jwk_from_pem(other_public_pem, kid="demo-k2")
        jwks = {"keys": [jwk1, jwk2]}
        base["jwks"] = jwks
        base["key_type"] = "jwks"
        base["key_text"] = json.dumps(jwks, indent=2, sort_keys=True)
        return base

    if kind in {"es256-pem", "es384-pem", "es512-pem"}:
        if kind == "es256-pem":
            private_pem, public_pem = _ec_p256_keypair()
            alg = "ES256"
            kid = "demo-ec1"
        elif kind == "es384-pem":
            private_pem, public_pem = _ec_p384_keypair()
            alg = "ES384"
            kid = "demo-ec384"
        else:
            private_pem, public_pem = _ec_p521_keypair()
            alg = "ES512"
            kid = "demo-ec521"
        token = sign_token(payload, key_path=None, key_text=private_pem, alg=alg, kid=kid)
        header, decoded = decode_token(token)
        return {
            "kind": kind,
            "alg": alg,
            "token": token,
            "header": header,
            "payload": decoded,
            "warnings": analyze_claims(decoded, header),
            "kid": kid,
            "verify_key": {"key_type": "pem", "key_text": public_pem},
            "sign_key": {"key_type": "pem", "key_text": private_pem},
            "key_type": "pem",
            "key_text": private_pem,
            **DEFAULT_POLICY,
        }

    if kind == "eddsa-pem":
        private_pem, public_pem = _ed25519_keypair()
        token = sign_token(
            payload, key_path=None, key_text=private_pem, alg="EdDSA", kid="demo-ed1"
        )
        header, decoded = decode_token(token)
        return {
            "kind": kind,
            "alg": "EdDSA",
            "token": token,
            "header": header,
            "payload": decoded,
            "warnings": analyze_claims(decoded, header),
            "kid": "demo-ed1",
            "verify_key": {"key_type": "pem", "key_text": public_pem},
            "sign_key": {"key_type": "pem", "key_text": private_pem},
            "key_type": "pem",
            "key_text": private_pem,
            **DEFAULT_POLICY,
        }

    raise ValueError("unknown sample kind")


def generate_key_preset(kind: str) -> dict[str, Any]:
    if kind not in SUPPORTED_KEY_PRESET_KINDS:
        raise ValueError("unknown key preset")

    private_pem, public_pem = _rsa_keypair()
    if kind == "pem-private":
        return {"key_type": "pem", "key_text": private_pem, "alg": "RS256"}
    if kind == "pem-public":
        return {"key_type": "pem", "key_text": public_pem, "alg": "RS256"}

    if kind in {"pem-ec-private", "pem-ec-public"}:
        ec_private, ec_public = _ec_p256_keypair()
        if kind == "pem-ec-private":
            return {"key_type": "pem", "key_text": ec_private, "alg": "ES256"}
        return {"key_type": "pem", "key_text": ec_public, "alg": "ES256"}

    if kind in {"pem-ec-p384-private", "pem-ec-p384-public"}:
        ec_private, ec_public = _ec_p384_keypair()
        if kind == "pem-ec-p384-private":
            return {"key_type": "pem", "key_text": ec_private, "alg": "ES384"}
        return {"key_type": "pem", "key_text": ec_public, "alg": "ES384"}

    if kind in {"pem-ec-p521-private", "pem-ec-p521-public"}:
        ec_private, ec_public = _ec_p521_keypair()
        if kind == "pem-ec-p521-private":
            return {"key_type": "pem", "key_text": ec_private, "alg": "ES512"}
        return {"key_type": "pem", "key_text": ec_public, "alg": "ES512"}

    if kind in {"pem-ed25519-private", "pem-ed25519-public"}:
        ed_private, ed_public = _ed25519_keypair()
        if kind == "pem-ed25519-private":
            return {"key_type": "pem", "key_text": ed_private, "alg": "EdDSA"}
        return {"key_type": "pem", "key_text": ed_public, "alg": "EdDSA"}

    jwk = jwk_from_pem(public_pem, kid="demo-k1")
    if kind == "jwk":
        return {
            "key_type": "jwk",
            "key_text": json.dumps(jwk, indent=2, sort_keys=True),
            "kid": "demo-k1",
            "alg": "RS256",
        }

    if kind == "jwk-ec":
        _, ec_public = _ec_p256_keypair()
        ec_jwk = jwk_from_pem(ec_public, kid="demo-ec1")
        return {
            "key_type": "jwk",
            "key_text": json.dumps(ec_jwk, indent=2, sort_keys=True),
            "kid": "demo-ec1",
            "alg": "ES256",
        }

    if kind == "jwk-ec-p384":
        _, ec_public = _ec_p384_keypair()
        ec_jwk = jwk_from_pem(ec_public, kid="demo-ec384")
        return {
            "key_type": "jwk",
            "key_text": json.dumps(ec_jwk, indent=2, sort_keys=True),
            "kid": "demo-ec384",
            "alg": "ES384",
        }

    if kind == "jwk-ec-p521":
        _, ec_public = _ec_p521_keypair()
        ec_jwk = jwk_from_pem(ec_public, kid="demo-ec521")
        return {
            "key_type": "jwk",
            "key_text": json.dumps(ec_jwk, indent=2, sort_keys=True),
            "kid": "demo-ec521",
            "alg": "ES512",
        }

    if kind == "jwk-okp":
        _, ed_public = _ed25519_keypair()
        okp_jwk = jwk_from_pem(ed_public, kid="demo-ed1")
        return {
            "key_type": "jwk",
            "key_text": json.dumps(okp_jwk, indent=2, sort_keys=True),
            "kid": "demo-ed1",
            "alg": "EdDSA",
        }

    _, other_public_pem = _rsa_keypair()
    jwk2 = jwk_from_pem(other_public_pem, kid="demo-k2")
    jwks = {"keys": [jwk, jwk2]}
    if kind == "jwks":
        return {
            "key_type": "jwks",
            "key_text": json.dumps(jwks, indent=2, sort_keys=True),
            "kid": "demo-k1",
            "alg": "RS256",
        }

    if kind == "jwks-ec":
        _, ec_public_1 = _ec_p256_keypair()
        _, ec_public_2 = _ec_p256_keypair()
        ec_jwk_1 = jwk_from_pem(ec_public_1, kid="demo-ec1")
        ec_jwk_2 = jwk_from_pem(ec_public_2, kid="demo-ec2")
        ec_jwks = {"keys": [ec_jwk_1, ec_jwk_2]}
        return {
            "key_type": "jwks",
            "key_text": json.dumps(ec_jwks, indent=2, sort_keys=True),
            "kid": "demo-ec1",
            "alg": "ES256",
        }

    if kind == "jwks-ec-p384":
        _, ec_public_1 = _ec_p384_keypair()
        _, ec_public_2 = _ec_p384_keypair()
        ec_jwk_1 = jwk_from_pem(ec_public_1, kid="demo-ec384-1")
        ec_jwk_2 = jwk_from_pem(ec_public_2, kid="demo-ec384-2")
        ec_jwks = {"keys": [ec_jwk_1, ec_jwk_2]}
        return {
            "key_type": "jwks",
            "key_text": json.dumps(ec_jwks, indent=2, sort_keys=True),
            "kid": "demo-ec384-1",
            "alg": "ES384",
        }

    if kind == "jwks-ec-p521":
        _, ec_public_1 = _ec_p521_keypair()
        _, ec_public_2 = _ec_p521_keypair()
        ec_jwk_1 = jwk_from_pem(ec_public_1, kid="demo-ec521-1")
        ec_jwk_2 = jwk_from_pem(ec_public_2, kid="demo-ec521-2")
        ec_jwks = {"keys": [ec_jwk_1, ec_jwk_2]}
        return {
            "key_type": "jwks",
            "key_text": json.dumps(ec_jwks, indent=2, sort_keys=True),
            "kid": "demo-ec521-1",
            "alg": "ES512",
        }

    if kind == "jwks-okp":
        _, ed_public_1 = _ed25519_keypair()
        _, ed_public_2 = _ed25519_keypair()
        okp_jwk_1 = jwk_from_pem(ed_public_1, kid="demo-ed1")
        okp_jwk_2 = jwk_from_pem(ed_public_2, kid="demo-ed2")
        okp_jwks = {"keys": [okp_jwk_1, okp_jwk_2]}
        return {
            "key_type": "jwks",
            "key_text": json.dumps(okp_jwks, indent=2, sort_keys=True),
            "kid": "demo-ed1",
            "alg": "EdDSA",
        }

    raise ValueError("unknown key preset")
