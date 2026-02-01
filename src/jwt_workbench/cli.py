from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

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


def _cmd_verify(args: argparse.Namespace) -> int:
    hmac_len = infer_hmac_key_len(args.key, args.key_text)
    header, payload = verify_token(
        token=args.token,
        key_path=args.key,
        key_text=args.key_text,
        jwk_path=args.jwk,
        jwks_path=args.jwks,
        kid=args.kid,
        alg=args.alg,
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

    p_verify = sub.add_parser("verify", help="Verify a JWT signature and claims")
    p_verify.add_argument("--token", required=True, help="JWT string")
    p_verify.add_argument("--alg", help="Override algorithm (e.g. HS256, RS256)")
    p_verify.add_argument("--key", help="Path to secret or PEM key")
    p_verify.add_argument("--key-text", help="Raw secret string (HS256)")
    p_verify.add_argument("--jwk", help="Path to JWK JSON file")
    p_verify.add_argument("--jwks", help="Path to JWKS JSON file")
    p_verify.add_argument("--kid", help="Key ID to select from JWKS")
    p_verify.set_defaults(func=_cmd_verify)

    p_sign = sub.add_parser("sign", help="Sign a JWT")
    p_sign.add_argument("--payload", help="JSON payload string")
    p_sign.add_argument("--payload-file", help="Path to JSON payload file")
    p_sign.add_argument("--alg", default="HS256", help="Algorithm (HS256 or RS256)")
    p_sign.add_argument("--key", help="Path to secret or PEM private key")
    p_sign.add_argument("--key-text", help="Raw secret string (HS256)")
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
