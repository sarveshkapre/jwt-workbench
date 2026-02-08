from __future__ import annotations

import json
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .core import analyze_claims, decode_token, jwk_from_pem, sign_token

SUPPORTED_SAMPLE_KINDS = frozenset({"hs256", "rs256-pem", "rs256-jwks", "none"})
SUPPORTED_KEY_PRESET_KINDS = frozenset({"pem-private", "pem-public", "jwk", "jwks"})
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

    if kind == "hs256":
        secret = "demo-secret-please-change"
        token = sign_token(payload, key_path=None, key_text=secret, alg="HS256", kid=None)
        header, decoded = decode_token(token)
        return {
            "kind": kind,
            "alg": "HS256",
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

    private_pem, public_pem = _rsa_keypair()
    token = sign_token(payload, key_path=None, key_text=private_pem, alg="RS256", kid="demo-k1")
    header, decoded = decode_token(token)
    base: dict[str, Any] = {
        "kind": kind,
        "alg": "RS256",
        "token": token,
        "header": header,
        "payload": decoded,
        "warnings": analyze_claims(decoded, header),
        "kid": "demo-k1",
        "verify_key": {"key_type": "pem", "key_text": public_pem},
        "sign_key": {"key_type": "pem", "key_text": private_pem},
        **DEFAULT_POLICY,
    }
    if kind == "rs256-pem":
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


def generate_key_preset(kind: str) -> dict[str, Any]:
    if kind not in SUPPORTED_KEY_PRESET_KINDS:
        raise ValueError("unknown key preset")

    private_pem, public_pem = _rsa_keypair()
    if kind == "pem-private":
        return {"key_type": "pem", "key_text": private_pem, "alg": "RS256"}
    if kind == "pem-public":
        return {"key_type": "pem", "key_text": public_pem, "alg": "RS256"}

    jwk = jwk_from_pem(public_pem, kid="demo-k1")
    if kind == "jwk":
        return {
            "key_type": "jwk",
            "key_text": json.dumps(jwk, indent=2, sort_keys=True),
            "kid": "demo-k1",
            "alg": "RS256",
        }

    _, other_public_pem = _rsa_keypair()
    jwk2 = jwk_from_pem(other_public_pem, kid="demo-k2")
    jwks = {"keys": [jwk, jwk2]}
    return {
        "key_type": "jwks",
        "key_text": json.dumps(jwks, indent=2, sort_keys=True),
        "kid": "demo-k1",
        "alg": "RS256",
    }
