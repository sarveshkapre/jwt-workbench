from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .core import (
    analyze_claims,
    decode_token,
    infer_hmac_key_len,
    jwk_from_pem,
    jwks_from_pem,
    sign_token,
    verify_token,
)
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


def _print_json(obj: object) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _emit_warnings(
    payload: dict[str, Any],
    header: dict[str, Any],
    hmac_len: int | None = None,
) -> None:
    warnings = analyze_claims(payload, header, hmac_key_len=hmac_len)
    if not warnings:
        return
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)


def _cmd_decode(args: argparse.Namespace) -> int:
    header, payload = decode_token(args.token)
    _emit_warnings(payload, header)
    _print_json({"header": header, "payload": payload})
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    header, payload = decode_token(args.token)
    if not args.no_warnings:
        _emit_warnings(payload, header)
    _print_json({"header": header, "payload": payload, "warnings": analyze_claims(payload, header)})
    return 0


def _cmd_sample(args: argparse.Namespace) -> int:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": "demo-user",
        "aud": "demo-aud",
        "iss": "demo-iss",
        "iat": now,
        "exp": now + int(args.exp_seconds),
    }

    kind = str(args.kind)
    if kind == "none":
        token = sign_token(payload, key_path=None, key_text=None, alg="none", kid=None)
        header, decoded = decode_token(token)
        _print_json(
            {
                "kind": kind,
                "alg": "none",
                "token": token,
                "header": header,
                "payload": decoded,
                "warnings": analyze_claims(decoded, header),
            }
        )
        return 0

    if kind == "hs256":
        secret = "demo-secret-please-change"
        token = sign_token(payload, key_path=None, key_text=secret, alg="HS256", kid=None)
        header, decoded = decode_token(token)
        _print_json(
            {
                "kind": kind,
                "alg": "HS256",
                "token": token,
                "header": header,
                "payload": decoded,
                "warnings": analyze_claims(
                    decoded, header, hmac_key_len=len(secret.encode("utf-8"))
                ),
                "verify_key": {"key_type": "secret", "key_text": secret},
            }
        )
        return 0

    if kind not in {"rs256-pem", "rs256-jwks"}:
        raise SystemExit(f"unknown sample kind: {kind}")

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
    }

    if kind == "rs256-pem":
        _print_json(base)
        return 0

    jwk1 = jwk_from_pem(public_pem, kid="demo-k1")
    other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_public_pem = (
        other_private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    jwk2 = jwk_from_pem(other_public_pem, kid="demo-k2")
    base["jwks"] = {"keys": [jwk1, jwk2]}
    _print_json(base)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    hmac_len = infer_hmac_key_len(args.key, args.key_text)
    audience: str | list[str] | None
    if not args.aud:
        audience = None
    else:
        items: list[str] = []
        for raw in args.aud:
            items.extend([part.strip() for part in str(raw).split(",") if part.strip()])
        if not items:
            audience = None
        elif len(items) == 1:
            audience = items[0]
        else:
            audience = items
    header, payload = verify_token(
        token=args.token,
        key_path=args.key,
        key_text=args.key_text,
        jwk_path=args.jwk,
        jwks_path=args.jwks,
        kid=args.kid,
        alg=args.alg,
        audience=audience,
        issuer=args.iss,
        leeway=args.leeway,
    )
    _emit_warnings(payload, header, hmac_len)
    _print_json({"valid": True, "header": header, "payload": payload})
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    payload = _load_payload(args)
    token = sign_token(
        payload=payload,
        key_path=args.key,
        key_text=args.key_text,
        alg=args.alg,
        kid=args.kid,
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
    parser.add_argument("--version", action="version", version="0.1.0")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_decode = sub.add_parser("decode", help="Decode a JWT without verifying signature")
    p_decode.add_argument("--token", required=True, help="JWT string")
    p_decode.set_defaults(func=_cmd_decode)

    p_inspect = sub.add_parser("inspect", help="Decode + show warnings (like the web UI)")
    p_inspect.add_argument("--token", required=True, help="JWT string")
    p_inspect.add_argument(
        "--no-warnings", action="store_true", help="Do not print warnings to stderr"
    )
    p_inspect.set_defaults(func=_cmd_inspect)

    p_sample = sub.add_parser("sample", help="Generate offline demo tokens/keys (no network)")
    p_sample.add_argument(
        "--kind",
        choices=["hs256", "rs256-pem", "rs256-jwks", "none"],
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
    p_verify.add_argument("--token", required=True, help="JWT string")
    p_verify.add_argument("--alg", help="Override algorithm (e.g. HS256, RS256)")
    p_verify.add_argument("--key", help="Path to secret or PEM key")
    p_verify.add_argument("--key-text", help="Raw secret string (HS256)")
    p_verify.add_argument("--jwk", help="Path to JWK JSON file")
    p_verify.add_argument("--jwks", help="Path to JWKS JSON file")
    p_verify.add_argument("--kid", help="Key ID to select from JWKS")
    p_verify.add_argument(
        "--aud",
        action="append",
        help="Expected audience (repeatable or comma-separated; enables aud claim verification)",
    )
    p_verify.add_argument("--iss", help="Expected issuer (enables iss claim verification)")
    p_verify.add_argument(
        "--leeway",
        type=int,
        default=0,
        help="Clock skew in seconds when verifying exp/nbf/iat (default: 0)",
    )
    p_verify.set_defaults(func=_cmd_verify)

    p_sign = sub.add_parser("sign", help="Sign a JWT")
    p_sign.add_argument("--payload", help="JSON payload string")
    p_sign.add_argument("--payload-file", help="Path to JSON payload file")
    p_sign.add_argument("--alg", default="HS256", help="Algorithm (HS256, RS256, or none)")
    p_sign.add_argument("--key", help="Path to secret or PEM private key (not used for alg=none)")
    p_sign.add_argument("--key-text", help="Raw secret string (HS256) (not used for alg=none)")
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
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
