from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from jwt_workbench.web import JWTWorkbenchHandler


def _load_schema_defs() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    schema_path = root / "schemas" / "web_api_responses.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    defs = schema.get("$defs")
    if not isinstance(defs, dict):
        raise AssertionError("schema missing $defs")
    return defs


_SCHEMA_DEFS = _load_schema_defs()


def _validate(def_name: str, instance: dict[str, Any]) -> None:
    if def_name not in _SCHEMA_DEFS:
        raise AssertionError(f"unknown schema def: {def_name}")
    # Validate with the full schema context so internal $refs to $defs resolve.
    schema: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": _SCHEMA_DEFS,
        "$ref": f"#/$defs/{def_name}",
    }
    jsonschema.Draft202012Validator(schema).validate(instance)


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


def test_web_api_responses_match_published_schema(web_base_url: str) -> None:
    status, _, err = _post_json(
        web_base_url,
        "/api/decode",
        {"token": "x.y.z"},
        content_type="text/plain",
    )
    assert status == 400
    _validate("ErrorResponse", err)

    status, _, sample = _post_json(web_base_url, "/api/sample", {"kind": "hs256"})
    assert status == 200
    _validate("SampleResponse", sample)

    token = str(sample["token"])
    secret = str(sample["key_text"])

    status, _, decoded = _post_json(web_base_url, "/api/decode", {"token": token})
    assert status == 200
    _validate("DecodeResponse", decoded)

    status, _, verified = _post_json(
        web_base_url,
        "/api/verify",
        {"token": token, "alg": "HS256", "key_type": "secret", "key_text": secret},
    )
    assert status == 200
    _validate("VerifyResponse", verified)

    status, _, signed = _post_json(
        web_base_url,
        "/api/sign",
        {"payload": '{"sub":"x","exp":2000000000}', "header": "{}", "alg": "none", "key_text": ""},
    )
    assert status == 200
    _validate("SignResponse", signed)

    status, _, exported = _post_json(web_base_url, "/api/export", {"token": token})
    assert status == 200
    _validate("ExportResponse", exported)

    status, _, preset = _post_json(web_base_url, "/api/key-preset", {"kind": "jwks"})
    assert status == 200
    _validate("KeyPresetResponse", preset)

    status, _, rs_sample = _post_json(web_base_url, "/api/sample", {"kind": "rs256-pem"})
    assert status == 200
    pem = str(rs_sample["key_text"])

    status, _, jwk = _post_json(web_base_url, "/api/jwk", {"pem": pem, "kid": "k1"})
    assert status == 200
    _validate("JwkResponse", jwk)

    status, _, jwks = _post_json(web_base_url, "/api/jwks", {"pem": pem, "kid": "k1"})
    assert status == 200
    _validate("JwksResponse", jwks)
