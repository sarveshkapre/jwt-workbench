from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from jwt import algorithms


def decode_token(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    return header, payload


def _looks_like_pem(text: str) -> bool:
    return "BEGIN" in text and "KEY" in text


def _looks_like_json(text: str) -> bool:
    return text.strip().startswith("{")


def _load_key_from_text(text: str, alg: str) -> Any:
    if alg.startswith("HS"):
        if _looks_like_pem(text) or _looks_like_json(text):
            raise ValueError("refusing to use PEM/JWK as HMAC secret")
        return text.encode("utf-8")
    return text


def _load_key_from_file(path: Path, alg: str) -> Any:
    content = path.read_text(encoding="utf-8").strip()
    if _looks_like_json(content):
        obj = json.loads(content)
        if "keys" in obj:
            raise ValueError("use jwks loader for JWKS files")
        if obj.get("kty") == "RSA":
            if alg.startswith("HS"):
                raise ValueError("refusing to use JWK as HMAC secret")
            return algorithms.RSAAlgorithm.from_jwk(json.dumps(obj))
    if _looks_like_pem(content):
        if alg.startswith("HS"):
            raise ValueError("refusing to use PEM as HMAC secret")
        return content
    return _load_key_from_text(content, alg)


def _select_jwks_key(jwks: dict[str, Any], kid: str | None) -> Any:
    keys = jwks.get("keys", [])
    if not keys:
        raise ValueError("JWKS has no keys")
    if kid:
        for key in keys:
            if key.get("kid") == kid:
                return algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        raise ValueError(f"kid not found in JWKS: {kid}")
    if len(keys) == 1:
        return algorithms.RSAAlgorithm.from_jwk(json.dumps(keys[0]))
    raise ValueError("JWKS has multiple keys; provide --kid")


def verify_token(
    token: str,
    key_path: str | None,
    key_text: str | None,
    jwk_path: str | None,
    jwks_path: str | None,
    kid: str | None,
    alg: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    header = jwt.get_unverified_header(token)
    alg = alg or header.get("alg")
    if not alg:
        raise ValueError("missing alg in header; supply --alg")
    if alg == "none":
        raise ValueError("refusing to verify alg=none")

    key: Any
    if jwk_path:
        jwk = json.loads(Path(jwk_path).read_text(encoding="utf-8"))
        key = algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    elif jwks_path:
        jwks = json.loads(Path(jwks_path).read_text(encoding="utf-8"))
        key = _select_jwks_key(jwks, kid)
    elif key_path:
        key = _load_key_from_file(Path(key_path), alg)
    elif key_text:
        key = _load_key_from_text(key_text, alg)
    else:
        raise ValueError("missing key material; provide --key, --key-text, --jwk, or --jwks")

    payload = jwt.decode(
        token,
        key=key,
        algorithms=[alg],
        options={"verify_aud": False, "verify_iss": False},
    )
    return header, payload


def sign_token(
    payload: dict[str, Any],
    key_path: str | None,
    key_text: str | None,
    alg: str,
    kid: str | None,
) -> str:
    key: Any
    if key_path:
        key = _load_key_from_file(Path(key_path), alg)
    elif key_text:
        key = _load_key_from_text(key_text, alg)
    else:
        raise ValueError("missing key material; provide --key or --key-text")

    headers = {"kid": kid} if kid else None
    return jwt.encode(payload, key=key, algorithm=alg, headers=headers)


def jwk_from_pem(pem_text: str, kid: str | None = None) -> dict[str, Any]:
    data = pem_text.encode("utf-8")
    try:
        key_any = load_pem_public_key(data)
    except ValueError:
        key_any = load_pem_private_key(data, password=None).public_key()
    if not isinstance(key_any, rsa.RSAPublicKey):
        raise ValueError("only RSA keys are supported for JWK conversion")
    key = key_any
    jwk_any = json.loads(algorithms.RSAAlgorithm.to_jwk(key))
    if not isinstance(jwk_any, dict):
        raise ValueError("invalid JWK output")
    jwk = cast(dict[str, Any], jwk_any)
    if kid:
        jwk["kid"] = kid
    return jwk


def jwks_from_pem(pem_text: str, kid: str | None = None) -> dict[str, Any]:
    return {"keys": [jwk_from_pem(pem_text, kid=kid)]}


def analyze_claims(
    payload: dict[str, Any],
    header: dict[str, Any],
    hmac_key_len: int | None = None,
) -> list[str]:
    warnings: list[str] = []
    alg = header.get("alg")
    if alg == "none":
        warnings.append("token uses alg=none (unsigned)")
    if alg and alg.startswith("HS") and hmac_key_len is not None and hmac_key_len < 32:
        warnings.append("HMAC secret is shorter than 32 bytes (weak)")

    now = int(time.time())
    exp = payload.get("exp")
    if exp is None:
        warnings.append("missing exp claim")
    else:
        try:
            exp_int = int(exp)
            if exp_int < now:
                warnings.append("token is expired")
            elif exp_int - now < 300:
                warnings.append("token expires within 5 minutes")
        except (TypeError, ValueError):
            warnings.append("exp claim is not an integer")

    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            if int(nbf) > now:
                warnings.append("token not valid yet (nbf in the future)")
        except (TypeError, ValueError):
            warnings.append("nbf claim is not an integer")

    iat = payload.get("iat")
    if iat is not None:
        try:
            if int(iat) > now:
                warnings.append("iat is in the future")
        except (TypeError, ValueError):
            warnings.append("iat claim is not an integer")

    if "aud" not in payload:
        warnings.append("missing aud claim")
    if "iss" not in payload:
        warnings.append("missing iss claim")

    return warnings


def infer_hmac_key_len(key_path: str | None, key_text: str | None) -> int | None:
    if key_text is not None:
        return len(key_text.encode("utf-8"))
    if key_path is None:
        return None
    content = Path(key_path).read_text(encoding="utf-8").strip()
    if _looks_like_pem(content) or _looks_like_json(content):
        return None
    return len(content.encode("utf-8"))
