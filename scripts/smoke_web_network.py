from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from jwt_workbench.samples import generate_sample


def _pick_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _post_json(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return int(resp.status), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return int(exc.code), json.loads(exc.read().decode("utf-8"))


def main() -> int:
    sample = generate_sample("rs256-jwks")
    token = sample["token"]
    kid = sample["kid"]
    jwks = json.loads(sample["key_text"])

    class IssuerHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
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
            self.send_response(404)
            self.end_headers()

    issuer = ThreadingHTTPServer(("127.0.0.1", 0), IssuerHandler)
    issuer_thread = threading.Thread(target=issuer.serve_forever, daemon=True)
    issuer_thread.start()
    issuer_host, issuer_port = issuer.server_address
    jwks_url = f"http://{issuer_host}:{issuer_port}/jwks"

    serve_port = _pick_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "jwt_workbench", "serve", "--port", str(serve_port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        base = f"http://127.0.0.1:{serve_port}"
        for _ in range(50):
            try:
                urllib.request.urlopen(base + "/", timeout=0.2).read()
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("serve did not become ready")

        status, body = _post_json(
            base + "/api/verify",
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
        if status != 400 or body.get("error") != "network fetch disabled; set allow_network=true":
            raise RuntimeError(f"expected network-disabled error, got {status}: {body}")

        status, body = _post_json(
            base + "/api/verify",
            {
                "token": token,
                "alg": "RS256",
                "key_type": "jwks",
                "key_text": "",
                "kid": kid,
                "jwks_url": jwks_url,
                "allow_network": True,
            },
        )
        if status != 200 or body.get("header", {}).get("alg") != "RS256":
            raise RuntimeError(f"expected verify success, got {status}: {body}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        issuer.shutdown()
        issuer.server_close()
        issuer_thread.join(timeout=5)

    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
