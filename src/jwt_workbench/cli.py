from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from jwt import exceptions as jwt_exceptions

from .core import (
    analyze_claims,
    decode_token,
    format_jwt_error,
    infer_hmac_key_len,
    jwk_from_pem,
    jwk_thumbprint_sha256,
    jwks_from_pem,
    load_verification_key_and_public_jwk,
    redact_jws_signature,
    sign_token,
    verify_token_with_key,
)
from .samples import generate_sample
from .version import __version__
from .web import serve


def _ensure_dict(obj: Any, context: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise SystemExit(f"{context} must be a JSON object")
    return obj


def _load_payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.payload and args.payload_file:
        raise SystemExit("use only one of --payload or --payload-file")
    if args.payload_file:
        obj = json.loads(Path(args.payload_file).read_text(encoding="utf-8"))
        return _ensure_dict(obj, "payload")
    if args.payload:
        obj = json.loads(args.payload)
        return _ensure_dict(obj, "payload")
    raise SystemExit("missing payload: use --payload or --payload-file")


def _load_headers(args: argparse.Namespace) -> dict[str, Any] | None:
    if args.headers and args.headers_file:
        raise SystemExit("use only one of --headers or --headers-file")
    if args.headers_file:
        obj = json.loads(Path(args.headers_file).read_text(encoding="utf-8"))
        headers = _ensure_dict(obj, "headers")
    elif args.headers:
        obj = json.loads(args.headers)
        headers = _ensure_dict(obj, "headers")
    else:
        return None
    return {k: v for k, v in headers.items() if k not in {"alg", "kid"}}


def _print_json(obj: object) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _load_token(token_arg: str) -> str:
    if token_arg != "-":
        return token_arg
    token = sys.stdin.read().strip()
    if not token:
        raise ValueError("stdin is empty; expected JWT")
    return token


def _load_text(text_arg: str, label: str) -> str:
    if text_arg != "-":
        return text_arg
    text = sys.stdin.read()
    if not text.strip():
        raise ValueError(f"stdin is empty; expected {label}")
    return text


def _emit_warnings(
    payload: dict[str, Any],
    header: dict[str, Any],
    hmac_len: int | None = None,
    *,
    now: int | None = None,
) -> None:
    warnings = analyze_claims(payload, header, hmac_key_len=hmac_len, now=now)
    if not warnings:
        return
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)


def _parse_allowlist(values: list[str] | None) -> str | list[str] | None:
    if not values:
        return None
    items: list[str] = []
    for raw in values:
        items.extend(part.strip() for part in str(raw).split(",") if part.strip())
    if not items:
        return None
    if len(items) == 1:
        return items[0]
    return items


def _parse_required_claims(values: list[str] | None) -> list[str] | None:
    if not values:
        return None
    items: list[str] = []
    for raw in values:
        items.extend(part.strip() for part in str(raw).split(",") if part.strip())
    if not items:
        return None
    return list(dict.fromkeys(items))


_VERIFY_POLICY_REQUIRED_CLAIMS: dict[str, list[str] | None] = {
    "legacy": None,
    "default": ["exp"],
    "strict": ["exp", "aud", "iss"],
}


def _validate_verify_args(args: argparse.Namespace) -> None:
    if args.key and args.key_text is not None:
        raise ValueError("use only one of --key or --key-text")

    use_local_key = bool(args.key or args.key_text is not None)
    use_jwk = bool(args.jwk)
    use_jwks = bool(args.jwks or args.jwks_cache or getattr(args, "jwks_url", None))
    selected = int(use_local_key) + int(use_jwk) + int(use_jwks)
    if selected > 1:
        raise ValueError(
            "provide one key source: (--key/--key-text) or --jwk or (--jwks/--jwks-url/--jwks-cache)"
        )
    if selected == 0:
        raise ValueError(
            "missing key material; provide --key, --key-text, --jwk, --jwks, --jwks-url, or --jwks-cache"
        )
    if getattr(args, "jwks_url", None) and args.jwks:
        raise ValueError("use only one of --jwks or --jwks-url")


def _validate_sign_args(args: argparse.Namespace) -> None:
    if args.key and args.key_text is not None:
        raise ValueError("use only one of --key or --key-text")
    if args.alg == "none":
        if args.key or args.key_text is not None:
            raise ValueError("alg=none does not accept key material")
        return
    if not args.key and args.key_text is None:
        raise ValueError("missing key material; provide --key or --key-text")


def _cmd_decode(args: argparse.Namespace) -> int:
    header, payload = decode_token(_load_token(args.token))
    _emit_warnings(payload, header)
    _print_json({"header": header, "payload": payload})
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    header, payload = decode_token(_load_token(args.token))
    if not args.no_warnings:
        _emit_warnings(payload, header)
    _print_json({"header": header, "payload": payload, "warnings": analyze_claims(payload, header)})
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    token = _load_token(args.token)
    header, payload = decode_token(token)
    _print_json(
        {
            "token_redacted": redact_jws_signature(token),
            "header": header,
            "payload": payload,
            "warnings": analyze_claims(payload, header),
            "notes": "JWT signature replaced with REDACTED for safe sharing",
        }
    )
    return 0


def _format_allowlist_warning(label: str, expected: str | list[str] | None) -> str:
    if expected is None:
        return f"{label} claim mismatch"
    if isinstance(expected, list):
        if not expected:
            return f"{label} claim mismatch"
        return f"{label} claim mismatch (expected one of: {', '.join(expected)})"
    if not expected.strip():
        return f"{label} claim mismatch"
    return f"{label} claim mismatch (expected: {expected})"


def _emit_warning_lines(warnings: list[str]) -> None:
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)


def _cmd_validate(args: argparse.Namespace) -> int:
    token = _load_token(args.token)
    header, payload = decode_token(token)

    if args.at is not None and int(args.at) < 0:
        raise ValueError("--at must be a non-negative integer")
    now = int(args.at) if args.at is not None else int(time.time())

    leeway = int(args.leeway)
    if leeway < 0:
        raise ValueError("leeway must be a non-negative integer")

    warnings = analyze_claims(payload, header, now=now)

    # If leeway is specified, recompute the "in the future" / "expired" warnings using leeway
    # semantics similar to verification.
    if leeway:
        filtered: list[str] = []
        for w in warnings:
            if w in {
                "token is expired",
                "token not valid yet (nbf in the future)",
                "iat is in the future",
            }:
                continue
            filtered.append(w)
        warnings = filtered

        exp = payload.get("exp")
        if exp is not None:
            try:
                exp_int = int(exp)
                if exp_int <= now - leeway:
                    warnings.append("token is expired")
                elif exp_int - now < 300:
                    warnings.append("token expires within 5 minutes")
            except (TypeError, ValueError):
                # analyze_claims already covers non-int exp
                pass

        nbf = payload.get("nbf")
        if nbf is not None:
            try:
                if int(nbf) > now + leeway:
                    warnings.append("token not valid yet (nbf in the future)")
            except (TypeError, ValueError):
                pass

        iat = payload.get("iat")
        if iat is not None:
            try:
                if int(iat) > now + leeway:
                    warnings.append("iat is in the future")
            except (TypeError, ValueError):
                pass

    audience = _parse_allowlist(args.aud)
    if audience is not None:
        aud_claim = payload.get("aud")
        aud_values: list[str] = []
        if isinstance(aud_claim, str):
            aud_values = [aud_claim]
        elif isinstance(aud_claim, list):
            aud_values = [item for item in aud_claim if isinstance(item, str)]
        expected_list = audience if isinstance(audience, list) else [audience]
        if not aud_values or not any(aud in expected_list for aud in aud_values):
            warnings.append(_format_allowlist_warning("aud", audience))

    issuer = _parse_allowlist(args.iss)
    if issuer is not None:
        iss_claim = payload.get("iss")
        expected_list = issuer if isinstance(issuer, list) else [issuer]
        if not isinstance(iss_claim, str) or iss_claim not in expected_list:
            warnings.append(_format_allowlist_warning("iss", issuer))

    required_claims = _parse_required_claims(args.require)
    if required_claims is None:
        policy = str(getattr(args, "policy", "legacy") or "legacy")
        if policy not in _VERIFY_POLICY_REQUIRED_CLAIMS:
            raise ValueError("unknown policy profile")
        required_claims = _VERIFY_POLICY_REQUIRED_CLAIMS[policy]
    if required_claims:
        for claim in required_claims:
            if claim not in payload:
                warnings.append(f"missing required claim: {claim}")

    # Keep a stable order while deduping.
    warnings = list(dict.fromkeys(warnings))

    _print_json(
        {
            "ok": not warnings,
            "header": header,
            "payload": payload,
            "warnings": warnings,
            "now": now,
            "leeway": leeway,
        }
    )
    if warnings:
        _emit_warning_lines(warnings)
        return 2
    return 0


def _cmd_sample(args: argparse.Namespace) -> int:
    sample = generate_sample(str(args.kind), exp_seconds=int(args.exp_seconds))
    output: dict[str, Any] = {
        "kind": sample["kind"],
        "alg": sample["alg"],
        "token": sample["token"],
        "header": sample["header"],
        "payload": sample["payload"],
        "warnings": sample["warnings"],
        "key_type": sample["key_type"],
        "key_text": sample["key_text"],
        "kid": sample["kid"],
        "aud": sample["aud"],
        "iss": sample["iss"],
        "leeway": sample["leeway"],
        "require": sample["require"],
    }
    for optional_key in ("verify_key", "sign_key", "jwks"):
        if optional_key in sample:
            output[optional_key] = sample[optional_key]
    _print_json(output)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    _validate_verify_args(args)
    if args.token == "-" and args.key_text == "-":
        raise ValueError("cannot read both token and key from stdin; provide one normally")
    if args.at is not None and int(args.at) < 0:
        raise ValueError("--at must be a non-negative integer")

    key_text: str | None
    if args.key_text is None:
        key_text = None
    else:
        key_text = _load_text(args.key_text, "key material")

    token = _load_token(args.token)
    header, _ = decode_token(token)
    alg = args.alg or header.get("alg")
    if not alg:
        raise ValueError("missing alg in header; supply --alg")

    hmac_len = infer_hmac_key_len(args.key, key_text)
    audience = _parse_allowlist(args.aud)
    issuer = _parse_allowlist(args.iss)
    required_claims = _parse_required_claims(args.require)
    if required_claims is None:
        policy = str(getattr(args, "policy", "legacy") or "legacy")
        if policy not in _VERIFY_POLICY_REQUIRED_CLAIMS:
            raise ValueError("unknown policy profile")
        required_claims = _VERIFY_POLICY_REQUIRED_CLAIMS[policy]

    key, public_jwk = load_verification_key_and_public_jwk(
        key_path=args.key,
        key_text=key_text,
        jwk_path=args.jwk,
        jwks_path=args.jwks,
        jwks_url=args.jwks_url,
        jwks_cache_path=args.jwks_cache,
        kid=args.kid,
        alg=str(alg),
    )

    thumbprint: str | None = None
    if public_jwk is not None:
        try:
            thumbprint = jwk_thumbprint_sha256(public_jwk)
        except ValueError:
            thumbprint = None

    try:
        header, payload = verify_token_with_key(
            token=token,
            key=key,
            alg=str(alg),
            audience=audience,
            issuer=issuer,
            leeway=args.leeway,
            required_claims=required_claims,
            at=args.at,
        )
    except jwt_exceptions.PyJWTError as exc:
        raise ValueError(format_jwt_error(exc, audience=audience, issuer=issuer)) from exc
    _emit_warnings(payload, header, hmac_len, now=args.at)
    output: dict[str, Any] = {"valid": True, "header": header, "payload": payload}
    if thumbprint:
        output["key_thumbprint_sha256"] = thumbprint
    _print_json(output)
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    _validate_sign_args(args)
    payload = _load_payload(args)
    key_text: str | None = args.key_text
    if args.alg != "none" and args.key_text == "-":
        key_text = _load_text(args.key_text, "key material")
    token = sign_token(
        payload=payload,
        key_path=args.key,
        key_text=key_text,
        alg=args.alg,
        kid=args.kid,
        headers=_load_headers(args),
    )
    print(token)
    return 0


def _cmd_jwk(args: argparse.Namespace) -> int:
    jwk = jwk_from_pem(Path(args.pem).read_text(encoding="utf-8"), kid=args.kid)
    _print_json(jwk)
    return 0


def _cmd_jwks(args: argparse.Namespace) -> int:
    jwks = jwks_from_pem(Path(args.pem).read_text(encoding="utf-8"), kid=args.kid)
    _print_json(jwks)
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    serve(host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="jwt-workbench")
    parser.add_argument("--version", action="version", version=__version__)

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_decode = sub.add_parser("decode", help="Decode a JWT without verifying signature")
    p_decode.add_argument("--token", required=True, help="JWT string (use '-' to read from stdin)")
    p_decode.set_defaults(func=_cmd_decode)

    p_inspect = sub.add_parser("inspect", help="Decode + show warnings (like the web UI)")
    p_inspect.add_argument("--token", required=True, help="JWT string (use '-' to read from stdin)")
    p_inspect.add_argument(
        "--no-warnings", action="store_true", help="Do not print warnings to stderr"
    )
    p_inspect.set_defaults(func=_cmd_inspect)

    p_validate = sub.add_parser(
        "validate",
        help="Decode + run claim hygiene checks (no signature verification; exits non-zero on issues)",
    )
    p_validate.add_argument(
        "--token", required=True, help="JWT string (use '-' to read from stdin)"
    )
    p_validate.add_argument(
        "--policy",
        choices=["legacy", "default", "strict"],
        default="legacy",
        help=(
            "Validation policy preset (default: legacy). "
            "legacy=require nothing; default=require exp; strict=require exp,aud,iss."
        ),
    )
    p_validate.add_argument(
        "--aud",
        action="append",
        help="Expected audience (repeatable or comma-separated; checks aud claim values)",
    )
    p_validate.add_argument(
        "--iss",
        action="append",
        help="Expected issuer (repeatable or comma-separated; checks iss claim value)",
    )
    p_validate.add_argument(
        "--leeway",
        type=int,
        default=0,
        help="Clock skew in seconds when evaluating exp/nbf/iat warnings (default: 0)",
    )
    p_validate.add_argument(
        "--at",
        type=int,
        help="Override current time as unix seconds for exp/nbf/iat warnings (debugging)",
    )
    p_validate.add_argument(
        "--require",
        action="append",
        help=(
            "Require claim(s) to exist (repeatable or comma-separated; supported: exp, nbf, "
            "iat, aud, iss)"
        ),
    )
    p_validate.set_defaults(func=_cmd_validate)

    p_export = sub.add_parser(
        "export", help="Export a copy-safe JSON bundle (redacts the signature)"
    )
    p_export.add_argument("--token", required=True, help="JWT string (use '-' to read from stdin)")
    p_export.set_defaults(func=_cmd_export)

    p_sample = sub.add_parser("sample", help="Generate offline demo tokens/keys (no network)")
    p_sample.add_argument(
        "--kind",
        choices=[
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
        ],
        default="hs256",
        help="Sample kind (default: hs256)",
    )
    p_sample.add_argument(
        "--exp-seconds",
        type=int,
        default=3600,
        help="Expiration seconds from now (default: 3600)",
    )
    p_sample.set_defaults(func=_cmd_sample)

    p_verify = sub.add_parser("verify", help="Verify a JWT signature and claims")
    p_verify.add_argument("--token", required=True, help="JWT string (use '-' to read from stdin)")
    p_verify.add_argument("--alg", help="Override algorithm (e.g. HS256, RS256, ES256, EdDSA)")
    p_verify.add_argument("--key", help="Path to secret or PEM key")
    p_verify.add_argument(
        "--key-text",
        help="Raw secret/key text (use '-' to read from stdin; HS256 or PEM as needed)",
    )
    p_verify.add_argument("--jwk", help="Path to JWK JSON file")
    p_verify.add_argument("--jwks", help="Path to JWKS JSON file")
    p_verify.add_argument("--jwks-url", help="JWKS URL (http(s); optional cache via --jwks-cache)")
    p_verify.add_argument(
        "--jwks-cache",
        help="Path to JWKS cache file (read from cache if jwks not provided; writes on verify)",
    )
    p_verify.add_argument("--kid", help="Key ID to select from JWKS")
    p_verify.add_argument(
        "--policy",
        choices=["legacy", "default", "strict"],
        default="legacy",
        help=(
            "Verification policy preset (default: legacy). "
            "legacy=require nothing; default=require exp; strict=require exp,aud,iss."
        ),
    )
    p_verify.add_argument(
        "--aud",
        action="append",
        help="Expected audience (repeatable or comma-separated; enables aud claim verification)",
    )
    p_verify.add_argument(
        "--iss",
        action="append",
        help="Expected issuer (repeatable or comma-separated; enables iss claim verification)",
    )
    p_verify.add_argument(
        "--leeway",
        type=int,
        default=0,
        help="Clock skew in seconds when verifying exp/nbf/iat (default: 0)",
    )
    p_verify.add_argument(
        "--at",
        type=int,
        help="Override current time as unix seconds for exp/nbf/iat verification (debugging)",
    )
    p_verify.add_argument(
        "--require",
        action="append",
        help=(
            "Require claim(s) to exist (repeatable or comma-separated; supported: exp, nbf, "
            "iat, aud, iss)"
        ),
    )
    p_verify.set_defaults(func=_cmd_verify)

    p_sign = sub.add_parser("sign", help="Sign a JWT")
    p_sign.add_argument("--payload", help="JSON payload string")
    p_sign.add_argument("--payload-file", help="Path to JSON payload file")
    p_sign.add_argument("--headers", help="JSON header object (optional)")
    p_sign.add_argument("--headers-file", help="Path to JSON header file (optional)")
    p_sign.add_argument(
        "--alg", default="HS256", help="Algorithm (HS256, RS256, ES256, EdDSA, or none)"
    )
    p_sign.add_argument("--key", help="Path to secret or PEM private key (not used for alg=none)")
    p_sign.add_argument(
        "--key-text",
        help="Raw secret/key text (use '-' to read from stdin) (not used for alg=none)",
    )
    p_sign.add_argument("--kid", help="Optional key id")
    p_sign.set_defaults(func=_cmd_sign)

    p_jwk = sub.add_parser("jwk", help="Convert PEM to JWK")
    p_jwk.add_argument("--pem", required=True, help="Path to PEM public key")
    p_jwk.add_argument("--kid", help="Optional key id")
    p_jwk.set_defaults(func=_cmd_jwk)

    p_jwks = sub.add_parser("jwks", help="Convert PEM to JWKS")
    p_jwks.add_argument("--pem", required=True, help="Path to PEM public key")
    p_jwks.add_argument("--kid", help="Optional key id")
    p_jwks.set_defaults(func=_cmd_jwks)

    p_serve = sub.add_parser("serve", help="Launch the jwt.io-style web UI")
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    p_serve.set_defaults(func=_cmd_serve)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except (ValueError, jwt_exceptions.PyJWTError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
