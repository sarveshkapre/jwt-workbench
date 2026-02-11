from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(url: str, timeout_seconds: float = 5.0) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.5):
                return
        except Exception:
            time.sleep(0.1)
    raise AssertionError(f"server did not start: {url}")


def test_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "jwt_workbench", "--help"], check=False)
    assert proc.returncode == 0


def test_inspect_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "jwt_workbench", "inspect", "--help"], check=False)
    assert proc.returncode == 0


def test_inspect_quiet_suppresses_warning_lines() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "none"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    token = json.loads(sample.stdout)["token"]

    normal = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "inspect",
            "--token",
            token,
            "--output",
            "text",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert normal.returncode == 0
    assert "warning:" in normal.stdout.lower()

    quiet = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "inspect",
            "--token",
            token,
            "--output",
            "text",
            "--quiet",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert quiet.returncode == 0
    assert "warning:" not in quiet.stdout.lower()


def test_sample_none_outputs_json() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "none"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["alg"] == "none"
    assert isinstance(data["token"], str)


def test_verify_invalid_token_is_clean_error() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "verify",
            "--token",
            "not-a-jwt",
            "--key-text",
            "secret123",
            "--alg",
            "HS256",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "error:" in proc.stderr.lower()


def test_validate_exit_codes_and_output() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "hs256"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    token = json.loads(sample.stdout)["token"]

    ok = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "validate", "--token", token],
        check=False,
        capture_output=True,
        text=True,
    )
    assert ok.returncode == 0
    ok_payload = json.loads(ok.stdout)
    assert ok_payload["ok"] is True

    bad = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "validate", "--token", token, "--aud", "wrong"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert bad.returncode != 0
    bad_payload = json.loads(bad.stdout)
    assert bad_payload["ok"] is False
    assert any("aud claim mismatch" in str(item) for item in bad_payload.get("warnings", []))

    bad_text = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "validate",
            "--token",
            token,
            "--aud",
            "wrong",
            "--output",
            "text",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert bad_text.returncode != 0
    assert "warning:" in bad_text.stdout.lower()

    bad_text_quiet = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "validate",
            "--token",
            token,
            "--aud",
            "wrong",
            "--output",
            "text",
            "--quiet",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert bad_text_quiet.returncode != 0
    assert "warning:" not in bad_text_quiet.stdout.lower()


def test_decode_reads_token_from_stdin() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "none"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    token = json.loads(sample.stdout)["token"]
    proc = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "decode", "--token", "-"],
        check=False,
        input=token,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    decoded = json.loads(proc.stdout)
    assert decoded["header"]["alg"] == "none"


def test_export_outputs_redacted_bundle() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "none"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    token = json.loads(sample.stdout)["token"]

    proc = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "export", "--token", token],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    exported = json.loads(proc.stdout)
    assert exported["token_redacted"].endswith(".REDACTED")
    assert isinstance(exported["header"], dict)
    assert isinstance(exported["payload"], dict)


def test_session_export_import_roundtrip_with_safe_defaults() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "hs256"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    sample_data = json.loads(sample.stdout)
    token = sample_data["token"]
    secret = sample_data["key_text"]

    with tempfile.TemporaryDirectory() as td:
        out_path = str(Path(td) / "session.json")
        exported_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "jwt_workbench",
                "session-export",
                "--token",
                token,
                "--alg",
                "HS256",
                "--key-type",
                "secret",
                "--key-text",
                secret,
                "--out",
                out_path,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert exported_proc.returncode == 0
        exported = json.loads(exported_proc.stdout)
        verify = exported["verify"]
        assert verify["key_type"] == "secret"
        assert "key_text" not in verify
        assert exported["key_material_included"] is False
        assert Path(out_path).exists()

        imported_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "jwt_workbench",
                "session-import",
                "--session",
                out_path,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert imported_proc.returncode == 0
        imported = json.loads(imported_proc.stdout)
        assert imported["token"] == token
        assert imported["verify"]["key_type"] == "secret"


def test_session_export_includes_sensitive_key_only_with_explicit_opt_in() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "hs256"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    sample_data = json.loads(sample.stdout)
    token = sample_data["token"]
    secret = sample_data["key_text"]

    no_private = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "session-export",
            "--token",
            token,
            "--alg",
            "HS256",
            "--key-type",
            "secret",
            "--key-text",
            secret,
            "--include-key-material",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert no_private.returncode == 0
    no_private_export = json.loads(no_private.stdout)
    assert "key_text" not in no_private_export["verify"]

    with_private = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "session-export",
            "--token",
            token,
            "--alg",
            "HS256",
            "--key-type",
            "secret",
            "--key-text",
            secret,
            "--include-key-material",
            "--include-private-key-material",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert with_private.returncode == 0
    with_private_export = json.loads(with_private.stdout)
    assert with_private_export["verify"]["key_text"] == secret


def test_verify_reads_key_from_stdin() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "rs256-pem"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    data = json.loads(sample.stdout)
    token = data["token"]
    key_text = data["verify_key"]["key_text"]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "verify",
            "--token",
            token,
            "--alg",
            "RS256",
            "--key-text",
            "-",
        ],
        check=False,
        input=key_text,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    verified = json.loads(proc.stdout)
    assert verified["valid"] is True
    assert isinstance(verified.get("key_thumbprint_sha256"), str)


def test_verify_quiet_suppresses_extra_text_output() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "hs256"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    data = json.loads(sample.stdout)
    token = data["token"]
    key_text = data["key_text"]

    normal = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "verify",
            "--token",
            token,
            "--alg",
            "HS256",
            "--key-text",
            key_text,
            "--output",
            "text",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert normal.returncode == 0
    assert "valid" in normal.stdout.lower()

    quiet = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "verify",
            "--token",
            token,
            "--alg",
            "HS256",
            "--key-text",
            key_text,
            "--output",
            "text",
            "--quiet",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert quiet.returncode == 0
    assert "valid" not in quiet.stdout.lower()


def test_verify_oidc_issuer_fetch_and_offline_cache_fallback() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "rs256-jwks"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    data = json.loads(sample.stdout)
    token = data["token"]
    jwks = data["jwks"]
    kid = data["kid"]

    class OIDCHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http handler API
            host, port = cast(tuple[str | bytes, int], self.server.server_address)
            host_text = host.decode("ascii") if isinstance(host, bytes) else host
            if self.path == "/issuer/.well-known/openid-configuration":
                body = json.dumps({"jwks_uri": f"http://{host_text}:{port}/jwks"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/jwks":
                body = json.dumps(jwks).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, _fmt: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), OIDCHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = cast(tuple[str | bytes, int], server.server_address)
    host_text = host.decode("ascii") if isinstance(host, bytes) else host
    issuer_url = f"http://{host_text}:{port}/issuer"

    with tempfile.TemporaryDirectory() as td:
        cache_path = str(Path(td) / "jwks-cache.json")
        try:
            online = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "jwt_workbench",
                    "verify",
                    "--token",
                    token,
                    "--alg",
                    "RS256",
                    "--oidc-issuer",
                    issuer_url,
                    "--jwks-cache",
                    cache_path,
                    "--kid",
                    kid,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            assert online.returncode == 0
            assert json.loads(online.stdout)["valid"] is True
            assert Path(cache_path).exists()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        # Offline: discovery fetch will fail, but cached JWKS should still allow verification.
        offline = subprocess.run(
            [
                sys.executable,
                "-m",
                "jwt_workbench",
                "verify",
                "--token",
                token,
                "--alg",
                "RS256",
                "--oidc-issuer",
                issuer_url,
                "--jwks-cache",
                cache_path,
                "--kid",
                kid,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert offline.returncode == 0
        assert json.loads(offline.stdout)["valid"] is True


def test_sign_accepts_headers() -> None:
    signed = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "sign",
            "--alg",
            "none",
            "--payload",
            '{"sub":"x"}',
            "--headers",
            '{"foo":"bar"}',
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert signed.returncode == 0
    token = signed.stdout.strip()

    decoded = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "decode", "--token", token],
        check=False,
        capture_output=True,
        text=True,
    )
    assert decoded.returncode == 0
    header = json.loads(decoded.stdout)["header"]
    assert header["foo"] == "bar"


def test_sign_output_json_bundle() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "sign",
            "--alg",
            "none",
            "--payload",
            '{"sub":"x","exp":2000000000}',
            "--output",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert isinstance(data.get("token"), str)
    assert isinstance(data.get("header"), dict)
    assert isinstance(data.get("payload"), dict)
    assert isinstance(data.get("warnings"), list)


def test_verify_required_claim_flag() -> None:
    signed = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "sign",
            "--alg",
            "HS256",
            "--payload",
            '{"sub":"x","exp":2000000000}',
            "--key-text",
            "secret123",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert signed.returncode == 0
    token = signed.stdout.strip()

    verified = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "verify",
            "--token",
            token,
            "--alg",
            "HS256",
            "--key-text",
            "secret123",
            "--require",
            "iss",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified.returncode != 0
    assert "missing required claim: iss" in verified.stderr.lower()


def test_verify_policy_strict_enforces_required_claims() -> None:
    signed = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "sign",
            "--alg",
            "HS256",
            "--payload",
            '{"sub":"x","aud":"a","exp":2000000000}',
            "--key-text",
            "secret123",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert signed.returncode == 0
    token = signed.stdout.strip()

    verified = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "verify",
            "--token",
            token,
            "--alg",
            "HS256",
            "--key-text",
            "secret123",
            "--policy",
            "strict",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified.returncode != 0
    assert "missing required claim" in verified.stderr.lower()


def test_verify_rejects_conflicting_key_inputs() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "verify",
            "--token",
            "x.y.z",
            "--alg",
            "HS256",
            "--key",
            "secret.txt",
            "--key-text",
            "secret123",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "use only one of --key or --key-text" in proc.stderr


def test_sign_none_rejects_key_material() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "sign",
            "--alg",
            "none",
            "--payload",
            '{"sub":"x"}',
            "--key-text",
            "ignored",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "alg=none does not accept key material" in proc.stderr


def test_serve_smoke_http_flow() -> None:
    port = _find_free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "jwt_workbench", "serve", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        base_url = f"http://127.0.0.1:{port}"
        _wait_for_server(base_url + "/")
        with urllib.request.urlopen(base_url + "/", timeout=2) as response:
            html = response.read().decode("utf-8")
            assert "JWT Workbench" in html

        request = urllib.request.Request(
            base_url + "/api/sample",
            data=json.dumps({"kind": "hs256"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            sample = json.loads(response.read().decode("utf-8"))
            assert sample["alg"] == "HS256"
            assert sample["key_type"] == "secret"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
