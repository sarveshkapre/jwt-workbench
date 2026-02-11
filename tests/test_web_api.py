from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import pytest

from jwt_workbench.core import jwk_from_pem, jwk_thumbprint_sha256
from jwt_workbench.samples import generate_sample
from jwt_workbench.web import JWTWorkbenchHandler


@pytest.fixture()
def web_base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), JWTWorkbenchHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    host_text = host.decode("ascii") if isinstance(host, bytes) else host
    try:
        yield f"http://{host_text}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _post_json(
    base_url: str,
    path: str,
    payload: dict[str, Any],
    *,
    content_type: str = "application/json",
) -> tuple[int, dict[str, str], dict[str, Any]]:
    req = urllib.request.Request(
        base_url + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": content_type},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            body = response.read().decode("utf-8")
            return int(response.status), dict(response.headers.items()), json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        parsed = json.loads(body) if body else {}
        return int(exc.code), dict(exc.headers.items()), parsed


def test_sample_and_security_headers(web_base_url: str) -> None:
    status, headers, payload = _post_json(web_base_url, "/api/sample", {"kind": "hs256"})
    assert status == 200
    assert payload["alg"] == "HS256"
    assert payload["require"] == ["exp", "aud", "iss"]
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_verify_required_claim_error(web_base_url: str) -> None:
    sign_status, _, signed = _post_json(
        web_base_url,
        "/api/sign",
        {
            "payload": '{"sub":"x","exp":2000000000}',
            "header": "{}",
            "alg": "HS256",
            "key_type": "secret",
            "key_text": "secret123",
        },
    )
    assert sign_status == 200
    token = signed["token"]

    verify_status, _, verified = _post_json(
        web_base_url,
        "/api/verify",
        {
            "token": token,
            "alg": "HS256",
            "key_type": "secret",
            "key_text": "secret123",
            "require": ["iss"],
        },
    )
    assert verify_status == 400
    assert verified["error"] == "missing required claim: iss"


def test_verify_at_time_override(web_base_url: str) -> None:
    sample_status, _, sample = _post_json(web_base_url, "/api/sample", {"kind": "hs256"})
    assert sample_status == 200
    token = sample["token"]
    exp = int(sample["payload"]["exp"])

    verify_status, _, verified = _post_json(
        web_base_url,
        "/api/verify",
        {
            "token": token,
            "alg": "HS256",
            "key_type": "secret",
            "key_text": sample["key_text"],
            "at": exp + 1,
        },
    )
    assert verify_status == 400
    assert verified["error"] == "token is expired"


def test_verify_returns_key_thumbprint_for_asymmetric_keys(web_base_url: str) -> None:
    sample_status, _, sample = _post_json(web_base_url, "/api/sample", {"kind": "rs256-pem"})
    assert sample_status == 200

    expected = jwk_thumbprint_sha256(jwk_from_pem(sample["key_text"]))

    verify_status, _, verified = _post_json(
        web_base_url,
        "/api/verify",
        {
            "token": sample["token"],
            "alg": "RS256",
            "key_type": "pem",
            "key_text": sample["key_text"],
        },
    )
    assert verify_status == 200
    assert verified["header"]["alg"] == "RS256"
    assert verified["key_thumbprint_sha256"] == expected


def test_verify_rejects_non_json_content_type(web_base_url: str) -> None:
    status, _, payload = _post_json(
        web_base_url,
        "/api/decode",
        {"token": "x.y.z"},
        content_type="text/plain",
    )
    assert status == 400
    assert payload["error"] == "Content-Type must be application/json"


def test_request_body_too_large(web_base_url: str) -> None:
    status, _, payload = _post_json(
        web_base_url,
        "/api/decode",
        {"token": "x" * (300 * 1024)},
    )
    assert status == 413
    assert payload["error"] == "request body too large"


def test_key_preset_jwks_shape(web_base_url: str) -> None:
    status, _, payload = _post_json(web_base_url, "/api/key-preset", {"kind": "jwks"})
    assert status == 200
    assert payload["key_type"] == "jwks"
    jwks = json.loads(payload["key_text"])
    assert isinstance(jwks.get("keys"), list)
    assert len(jwks["keys"]) == 2


def test_export_redacts_signature(web_base_url: str) -> None:
    sample_status, _, sample = _post_json(web_base_url, "/api/sample", {"kind": "hs256"})
    assert sample_status == 200
    token = sample["token"]

    status, _, exported = _post_json(web_base_url, "/api/export", {"token": token})
    assert status == 200
    assert exported["token_redacted"].split(".")[2] == "REDACTED"
    assert exported["header"]["alg"] == "HS256"
    assert isinstance(exported["payload"], dict)
    assert isinstance(exported["warnings"], list)


def test_session_export_and_import_with_safe_defaults(web_base_url: str) -> None:
    sample_status, _, sample = _post_json(web_base_url, "/api/sample", {"kind": "hs256"})
    assert sample_status == 200
    token = sample["token"]

    status, _, exported = _post_json(
        web_base_url,
        "/api/session-export",
        {
            "token": token,
            "alg": "HS256",
            "key_type": "secret",
            "key_text": sample["key_text"],
            "include_key_material": False,
        },
    )
    assert status == 200
    session = exported["session"]
    assert session["key_material_included"] is False
    assert "key_text" not in session["verify"]

    import_status, _, imported = _post_json(
        web_base_url,
        "/api/session-import",
        {"session": session},
    )
    assert import_status == 200
    imported_session = imported["session"]
    assert imported_session["token"] == token
    assert imported_session["verify"]["key_type"] == "secret"


def test_session_export_requires_explicit_private_key_opt_in(web_base_url: str) -> None:
    sample_status, _, sample = _post_json(web_base_url, "/api/sample", {"kind": "hs256"})
    assert sample_status == 200
    token = sample["token"]
    secret = sample["key_text"]

    no_private_status, _, no_private = _post_json(
        web_base_url,
        "/api/session-export",
        {
            "token": token,
            "alg": "HS256",
            "key_type": "secret",
            "key_text": secret,
            "include_key_material": True,
        },
    )
    assert no_private_status == 200
    assert "key_text" not in no_private["session"]["verify"]

    with_private_status, _, with_private = _post_json(
        web_base_url,
        "/api/session-export",
        {
            "token": token,
            "alg": "HS256",
            "key_type": "secret",
            "key_text": secret,
            "include_key_material": True,
            "include_private_key_material": True,
        },
    )
    assert with_private_status == 200
    assert with_private["session"]["verify"]["key_text"] == secret


def test_sign_rejects_secret_for_ps_alg(web_base_url: str) -> None:
    status, _, payload = _post_json(
        web_base_url,
        "/api/sign",
        {
            "payload": '{"sub":"x","exp":2000000000}',
            "header": "{}",
            "alg": "PS256",
            "key_type": "secret",
            "key_text": "secret123",
        },
    )
    assert status == 400
    assert payload["error"] == "non-HS signing requires key_type=pem"


def test_verify_supports_jwks_url_and_cache_with_explicit_network_opt_in(
    web_base_url: str, tmp_path: Any
) -> None:
    sample = generate_sample("rs256-jwks")
    token = sample["token"]
    kid = sample["kid"]
    jwks = json.loads(sample["key_text"])
    jwk = next(item for item in jwks["keys"] if item.get("kid") == kid)
    expected_thumbprint = jwk_thumbprint_sha256(jwk)

    class _IssuerHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/jwks":
                body = json.dumps(jwks).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/.well-known/openid-configuration":
                server = cast(ThreadingHTTPServer, self.server)
                _, port = server.server_address
                config = {"jwks_uri": f"http://127.0.0.1:{port}/jwks"}
                body = json.dumps(config).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    issuer_server = ThreadingHTTPServer(("127.0.0.1", 0), _IssuerHandler)
    issuer_thread = threading.Thread(target=issuer_server.serve_forever, daemon=True)
    issuer_thread.start()
    _, issuer_port = issuer_server.server_address
    issuer_base = f"http://127.0.0.1:{issuer_port}"
    jwks_url = f"{issuer_base}/jwks"
    cache_path = str(tmp_path / "jwks-cache.json")

    try:
        status, _, payload = _post_json(
            web_base_url,
            "/api/verify",
            {
                "token": token,
                "alg": "RS256",
                "key_type": "jwks",
                "key_text": "",
                "kid": kid,
                "jwks_url": jwks_url,
                "allow_network": False,
            },
        )
        assert status == 400
        assert payload["error"] == "network fetch disabled; set allow_network=true"

        status, _, payload = _post_json(
            web_base_url,
            "/api/verify",
            {
                "token": token,
                "alg": "RS256",
                "key_type": "jwks",
                "key_text": "",
                "kid": kid,
                "jwks_url": jwks_url,
                "jwks_cache_path": cache_path,
                "allow_network": True,
            },
        )
        assert status == 200
        assert payload["header"]["alg"] == "RS256"
        assert payload["key_thumbprint_sha256"] == expected_thumbprint
        assert os.path.exists(cache_path)

        status, _, payload = _post_json(
            web_base_url,
            "/api/verify",
            {
                "token": token,
                "alg": "RS256",
                "key_type": "jwks",
                "key_text": "",
                "kid": kid,
                "jwks_cache_path": cache_path,
                "allow_network": False,
            },
        )
        assert status == 200
        assert payload["key_thumbprint_sha256"] == expected_thumbprint

        status, _, payload = _post_json(
            web_base_url,
            "/api/verify",
            {
                "token": token,
                "alg": "RS256",
                "key_type": "jwks",
                "key_text": "",
                "kid": kid,
                "oidc_issuer": issuer_base,
                "jwks_cache_path": cache_path,
                "allow_network": True,
            },
        )
        assert status == 200
        assert payload["key_thumbprint_sha256"] == expected_thumbprint
    finally:
        issuer_server.shutdown()
        issuer_server.server_close()
        issuer_thread.join(timeout=5)
