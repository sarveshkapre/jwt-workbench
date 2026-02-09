from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from jwt import algorithms
from jwt import exceptions as jwt_exceptions

_SUPPORTED_REQUIRED_CLAIMS = frozenset({"exp", "nbf", "iat", "aud", "iss"})


def decode_token(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    header = jwt.get_unverified_header(token)
    # "Decode" mode is intentionally non-validating: it should parse header/payload even if
    # time-based claims are expired or issuer/audience don't match.
    payload = jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_nbf": False,
            "verify_iat": False,
            "verify_aud": False,
            "verify_iss": False,
            "verify_sub": False,
            "verify_jti": False,
        },
    )
    return header, payload


def redact_jws_signature(token: str, replacement: str = "REDACTED") -> str:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("expected a JWS with three dot-separated parts")
    if not replacement or "." in replacement:
        raise ValueError("invalid replacement")
    return f"{parts[0]}.{parts[1]}.{replacement}"


def _looks_like_pem(text: str) -> bool:
    return "BEGIN" in text and "KEY" in text


def _looks_like_json(text: str) -> bool:
    return text.strip().startswith("{")


def _expected_jwk_kty_for_alg(alg: str) -> str | None:
    if alg.startswith("HS"):
        return None
    if alg.startswith(("RS", "PS")):
        return "RSA"
    if alg.startswith("ES"):
        return "EC"
    if alg == "EdDSA":
        return "OKP"
    return None


def _jwk_to_key(jwk: dict[str, Any], *, alg: str | None) -> Any:
    kty = jwk.get("kty")
    if not isinstance(kty, str) or not kty.strip():
        raise ValueError("JWK missing kty")
    expected_kty = _expected_jwk_kty_for_alg(alg) if alg else None
    if expected_kty and kty != expected_kty:
        raise ValueError(f"JWK kty {kty} does not match algorithm {alg} (expected {expected_kty})")

    jwk_json = json.dumps(jwk)
    if kty == "RSA":
        return algorithms.RSAAlgorithm.from_jwk(jwk_json)
    if kty == "EC":
        return algorithms.ECAlgorithm.from_jwk(jwk_json)
    if kty == "OKP":
        return algorithms.OKPAlgorithm.from_jwk(jwk_json)
    raise ValueError(f"unsupported JWK kty: {kty}")


def _load_key_from_text(text: str, alg: str) -> Any:
    if alg.startswith("HS"):
        if _looks_like_pem(text) or _looks_like_json(text):
            raise ValueError("refusing to use PEM/JWK as HMAC secret")
        return text.encode("utf-8")
    if _looks_like_json(text):
        raise ValueError("expected PEM text, got JSON (use JWK/JWKS inputs instead)")
    return text


def _load_key_from_file(path: Path, alg: str) -> Any:
    content = path.read_text(encoding="utf-8").strip()
    if _looks_like_json(content):
        obj = json.loads(content)
        if "keys" in obj:
            raise ValueError("use jwks loader for JWKS files")
        if alg.startswith("HS"):
            raise ValueError("refusing to use JWK as HMAC secret")
        if not isinstance(obj, dict):
            raise ValueError("invalid JWK file")
        return _jwk_to_key(cast(dict[str, Any], obj), alg=alg)
    if _looks_like_pem(content):
        if alg.startswith("HS"):
            raise ValueError("refusing to use PEM as HMAC secret")
        return content
    return _load_key_from_text(content, alg)


def _select_jwks_key(jwks: dict[str, Any], kid: str | None, *, alg: str | None) -> Any:
    keys = jwks.get("keys", [])
    if not keys:
        raise ValueError("JWKS has no keys")
    if not isinstance(keys, list):
        raise ValueError("JWKS keys must be a list")

    jwk_candidates: list[dict[str, Any]] = []
    for item in keys:
        if isinstance(item, dict):
            jwk_candidates.append(cast(dict[str, Any], item))

    if kid:
        for jwk in jwk_candidates:
            if jwk.get("kid") == kid:
                return _jwk_to_key(jwk, alg=alg)
        raise ValueError(f"kid not found in JWKS: {kid}")

    if len(jwk_candidates) == 1:
        return _jwk_to_key(jwk_candidates[0], alg=alg)

    expected_kty = _expected_jwk_kty_for_alg(alg) if alg else None
    if expected_kty:
        matches = [jwk for jwk in jwk_candidates if jwk.get("kty") == expected_kty]
        if len(matches) == 1:
            return _jwk_to_key(matches[0], alg=alg)

    raise ValueError("JWKS has multiple keys; provide --kid")


def _normalize_allowlist(
    value: str | list[str] | None,
) -> tuple[str | None, list[str] | None]:
    if value is None:
        return None, None
    if isinstance(value, str):
        cleaned = value.strip()
        return (cleaned or None), None
    if isinstance(value, list):
        cleaned_list = [item.strip() for item in value if isinstance(item, str) and item.strip()]
        if not cleaned_list:
            return None, None
        if len(cleaned_list) == 1:
            return cleaned_list[0], None
        return None, cleaned_list
    raise ValueError("allowlist must be a string or list of strings")


def _enforce_issuer_allowlist(payload: dict[str, Any], issuers: list[str]) -> None:
    iss = payload.get("iss")
    if not isinstance(iss, str) or not iss.strip():
        raise jwt_exceptions.InvalidIssuerError("iss claim missing or not a string")
    if iss not in issuers:
        expected = ", ".join(issuers)
        raise jwt_exceptions.InvalidIssuerError(f"iss claim mismatch (expected one of: {expected})")


def _normalize_required_claims(
    required_claims: str | list[str] | None,
) -> list[str] | None:
    if required_claims is None:
        return None
    items: list[str] = []
    if isinstance(required_claims, str):
        items = [part.strip() for part in required_claims.split(",")]
    elif isinstance(required_claims, list):
        for item in required_claims:
            if not isinstance(item, str):
                raise ValueError("required claims must be strings")
            items.extend(part.strip() for part in item.split(","))
    else:
        raise ValueError("required claims must be a string or list of strings")

    cleaned: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not item:
            continue
        if item not in _SUPPORTED_REQUIRED_CLAIMS:
            supported = ", ".join(sorted(_SUPPORTED_REQUIRED_CLAIMS))
            raise ValueError(f"unsupported required claim: {item} (supported: {supported})")
        if item not in seen:
            seen.add(item)
            cleaned.append(item)
    return cleaned or None


def _load_jwks_from_paths(
    jwks_path: str | None,
    jwks_cache_path: str | None,
    jwks_url: str | None = None,
) -> dict[str, Any]:
    if jwks_url:
        try:
            jwks = _fetch_jwks(jwks_url)
        except Exception as exc:  # noqa: BLE001 - caller-facing error path
            if jwks_cache_path:
                cache_path = Path(jwks_cache_path)
                if cache_path.exists():
                    return cast(dict[str, Any], json.loads(cache_path.read_text(encoding="utf-8")))
            raise ValueError(f"failed to fetch JWKS from url: {exc}") from exc
        if jwks_cache_path:
            cache_path = Path(jwks_cache_path)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(
                json.dumps(jwks, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        return jwks
    if jwks_path:
        jwks = cast(dict[str, Any], json.loads(Path(jwks_path).read_text(encoding="utf-8")))
        if jwks_cache_path:
            cache_path = Path(jwks_cache_path)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(
                json.dumps(jwks, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        return jwks
    if jwks_cache_path:
        cache_path = Path(jwks_cache_path)
        if not cache_path.exists():
            raise ValueError("JWKS cache file not found; provide --jwks to populate it")
        return cast(dict[str, Any], json.loads(cache_path.read_text(encoding="utf-8")))
    raise ValueError("missing JWKS material; provide --jwks or --jwks-cache")


def load_key_from_material(key_text: str, alg: str, kind: str, kid: str | None = None) -> Any:
    if kind == "secret":
        return _load_key_from_text(key_text, alg)
    if kind == "pem":
        if _looks_like_json(key_text):
            raise ValueError("expected PEM text, got JSON")
        return _load_key_from_text(key_text, alg)
    if kind == "jwk":
        obj = json.loads(key_text)
        if not isinstance(obj, dict):
            raise ValueError("JWK must be an object")
        if "keys" in obj:
            raise ValueError("use jwks for multiple keys")
        return _jwk_to_key(cast(dict[str, Any], obj), alg=alg)
    if kind == "jwks":
        obj = json.loads(key_text)
        if not isinstance(obj, dict):
            raise ValueError("JWKS must be an object")
        return _select_jwks_key(cast(dict[str, Any], obj), kid, alg=alg)
    raise ValueError(f"unknown key kind: {kind}")


def verify_token_with_key(
    token: str,
    key: Any,
    alg: str | None,
    audience: str | list[str] | None = None,
    issuer: str | list[str] | None = None,
    leeway: int = 0,
    required_claims: str | list[str] | None = None,
    at: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    header = jwt.get_unverified_header(token)
    alg = alg or header.get("alg")
    if not alg:
        raise ValueError("missing alg in header; supply alg")
    if alg == "none":
        raise ValueError("refusing to verify alg=none")
    issuer_value, issuer_allowlist = _normalize_allowlist(issuer)
    required = _normalize_required_claims(required_claims)
    options: dict[str, Any] = {
        "verify_aud": audience is not None,
        "verify_iss": issuer_value is not None,
    }
    if required:
        options["require"] = required
    if at is not None:
        # PyJWT doesn't support overriding current time; when requested we disable built-in
        # time validation and apply our own checks against the caller-provided timestamp.
        options["verify_exp"] = False
        options["verify_nbf"] = False
        options["verify_iat"] = False
    payload = jwt.decode(
        token,
        key=key,
        algorithms=[alg],
        audience=audience,
        issuer=issuer_value,
        leeway=leeway,
        options=options,
    )
    if at is not None:
        _validate_time_claims(payload, now=float(at), leeway=float(leeway))
    if issuer_allowlist:
        _enforce_issuer_allowlist(payload, issuer_allowlist)
    return header, payload


def verify_token(
    token: str,
    key_path: str | None,
    key_text: str | None,
    jwk_path: str | None,
    jwks_path: str | None,
    kid: str | None,
    alg: str | None,
    jwks_url: str | None = None,
    audience: str | list[str] | None = None,
    issuer: str | list[str] | None = None,
    leeway: int = 0,
    jwks_cache_path: str | None = None,
    required_claims: str | list[str] | None = None,
    at: int | None = None,
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
        if not isinstance(jwk, dict):
            raise ValueError("JWK must be an object")
        key = _jwk_to_key(cast(dict[str, Any], jwk), alg=alg)
    elif jwks_path or jwks_cache_path or jwks_url:
        jwks = _load_jwks_from_paths(jwks_path, jwks_cache_path, jwks_url)
        key = _select_jwks_key(jwks, kid, alg=alg)
    elif key_path:
        key = _load_key_from_file(Path(key_path), alg)
    elif key_text:
        key = _load_key_from_text(key_text, alg)
    else:
        raise ValueError(
            "missing key material; provide --key, --key-text, --jwk, --jwks, --jwks-url, or --jwks-cache"
        )

    return verify_token_with_key(
        token,
        key=key,
        alg=alg,
        audience=audience,
        issuer=issuer,
        leeway=leeway,
        required_claims=required_claims,
        at=at,
    )


def sign_token(
    payload: dict[str, Any],
    key_path: str | None,
    key_text: str | None,
    alg: str,
    kid: str | None,
    headers: dict[str, Any] | None = None,
) -> str:
    if alg == "none":
        none_headers: dict[str, Any] = {}
        if headers:
            none_headers.update(headers)
        if kid:
            none_headers["kid"] = kid
        return jwt.encode(
            payload,
            key=cast(Any, None),
            algorithm="none",
            headers=none_headers or None,
        )

    key: Any
    if key_path:
        key = _load_key_from_file(Path(key_path), alg)
    elif key_text:
        key = _load_key_from_text(key_text, alg)
    else:
        raise ValueError("missing key material; provide --key or --key-text")

    merged_headers: dict[str, Any] = {}
    if headers:
        merged_headers.update(headers)
    if kid:
        merged_headers["kid"] = kid
    return jwt.encode(payload, key=key, algorithm=alg, headers=merged_headers or None)


def jwk_from_pem(pem_text: str, kid: str | None = None) -> dict[str, Any]:
    data = pem_text.encode("utf-8")
    try:
        key_any: Any = load_pem_public_key(data)
    except ValueError:
        key_any = load_pem_private_key(data, password=None)

    key = (
        key_any.public_key()
        if hasattr(key_any, "public_key")
        else key_any  # pragma: no cover - defensive
    )

    if isinstance(key, rsa.RSAPublicKey):
        jwk_any = json.loads(algorithms.RSAAlgorithm.to_jwk(key))
    elif isinstance(key, ec.EllipticCurvePublicKey):
        jwk_any = json.loads(algorithms.ECAlgorithm.to_jwk(key))
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        jwk_any = json.loads(algorithms.OKPAlgorithm.to_jwk(key))
    else:
        raise ValueError("unsupported key type for JWK conversion")

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
    *,
    now: int | None = None,
) -> list[str]:
    warnings: list[str] = []
    alg = header.get("alg")
    if alg == "none":
        warnings.append("token uses alg=none (unsigned)")
    if alg and alg.startswith("HS") and hmac_key_len is not None and hmac_key_len < 32:
        warnings.append("HMAC secret is shorter than 32 bytes (weak)")

    now_ts = int(time.time()) if now is None else int(now)
    exp = payload.get("exp")
    if exp is None:
        warnings.append("missing exp claim")
    else:
        try:
            exp_int = int(exp)
            if exp_int < now_ts:
                warnings.append("token is expired")
            elif exp_int - now_ts < 300:
                warnings.append("token expires within 5 minutes")
        except (TypeError, ValueError):
            warnings.append("exp claim is not an integer")

    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            if int(nbf) > now_ts:
                warnings.append("token not valid yet (nbf in the future)")
        except (TypeError, ValueError):
            warnings.append("nbf claim is not an integer")

    iat = payload.get("iat")
    if iat is not None:
        try:
            if int(iat) > now_ts:
                warnings.append("iat is in the future")
        except (TypeError, ValueError):
            warnings.append("iat claim is not an integer")

    aud = payload.get("aud")
    if aud is None:
        warnings.append("missing aud claim")
    elif isinstance(aud, list):
        if not aud:
            warnings.append("aud claim list is empty")
        elif not all(isinstance(item, str) for item in aud):
            warnings.append("aud claim list must contain strings")
    elif not isinstance(aud, str):
        warnings.append("aud claim must be a string or list of strings")

    iss = payload.get("iss")
    if iss is None:
        warnings.append("missing iss claim")
    elif not isinstance(iss, str):
        warnings.append("iss claim must be a string")

    return warnings


def _validate_time_claims(payload: dict[str, Any], *, now: float, leeway: float) -> None:
    if "exp" in payload:
        try:
            exp = int(payload["exp"])
        except (TypeError, ValueError):
            raise jwt_exceptions.DecodeError(
                "Expiration Time claim (exp) must be an integer."
            ) from None
        if exp <= (now - leeway):
            raise jwt_exceptions.ExpiredSignatureError("Signature has expired")

    if "nbf" in payload:
        try:
            nbf = int(payload["nbf"])
        except (TypeError, ValueError):
            raise jwt_exceptions.DecodeError("Not Before claim (nbf) must be an integer.") from None
        if nbf > (now + leeway):
            raise jwt_exceptions.ImmatureSignatureError("The token is not yet valid (nbf)")

    if "iat" in payload:
        try:
            iat = int(payload["iat"])
        except (TypeError, ValueError):
            raise jwt_exceptions.InvalidIssuedAtError(
                "Issued At claim (iat) must be an integer."
            ) from None
        if iat > (now + leeway):
            raise jwt_exceptions.ImmatureSignatureError("The token is not yet valid (iat)")


def _fetch_jwks(url: str, *, timeout: float = 3.0, max_bytes: int = 512 * 1024) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("JWKS url must be http(s)")

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError("JWKS response too large")

    try:
        parsed_json = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("JWKS url did not return valid JSON") from exc
    if not isinstance(parsed_json, dict):
        raise ValueError("JWKS must be an object")
    keys = parsed_json.get("keys")
    if not isinstance(keys, list):
        raise ValueError("JWKS keys must be a list")
    return cast(dict[str, Any], parsed_json)


def infer_hmac_key_len(key_path: str | None, key_text: str | None) -> int | None:
    if key_text is not None:
        return len(key_text.encode("utf-8"))
    if key_path is None:
        return None
    content = Path(key_path).read_text(encoding="utf-8").strip()
    if _looks_like_pem(content) or _looks_like_json(content):
        return None
    return len(content.encode("utf-8"))


def _format_allowlist(label: str, expected: str | list[str] | None) -> str:
    if expected is None:
        return f"{label} claim mismatch"
    if isinstance(expected, list):
        if not expected:
            return f"{label} claim mismatch"
        return f"{label} claim mismatch (expected one of: {', '.join(expected)})"
    if not expected.strip():
        return f"{label} claim mismatch"
    return f"{label} claim mismatch (expected: {expected})"


def format_jwt_error(
    exc: jwt_exceptions.PyJWTError,
    *,
    audience: str | list[str] | None = None,
    issuer: str | list[str] | None = None,
) -> str:
    if isinstance(exc, jwt_exceptions.ExpiredSignatureError):
        return "token is expired"
    if isinstance(exc, jwt_exceptions.ImmatureSignatureError):
        msg = str(exc).lower()
        if "iat" in msg:
            return "iat is in the future"
        return "token is not valid yet (nbf in the future)"
    if isinstance(exc, jwt_exceptions.InvalidIssuedAtError):
        return "iat claim is not an integer"
    if isinstance(exc, jwt_exceptions.InvalidAudienceError):
        return _format_allowlist("aud", audience)
    if isinstance(exc, jwt_exceptions.InvalidIssuerError):
        return _format_allowlist("iss", issuer)
    if isinstance(exc, jwt_exceptions.MissingRequiredClaimError):
        claim = getattr(exc, "claim", None)
        if isinstance(claim, str) and claim:
            return f"missing required claim: {claim}"
        return "missing required claim"
    if isinstance(exc, jwt_exceptions.InvalidSignatureError):
        return "signature verification failed"
    if isinstance(exc, jwt_exceptions.DecodeError):
        msg = str(exc).lower()
        if "expiration time claim" in msg or "(exp)" in msg:
            return "exp claim is not an integer"
        if "not before claim" in msg or "(nbf)" in msg:
            return "nbf claim is not an integer"
        return "invalid token format"
    return str(exc)
