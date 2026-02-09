from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from typing import Any

import pytest

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
