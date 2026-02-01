from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .core import (
    analyze_claims,
    decode_token,
    infer_hmac_key_len,
    jwk_from_pem,
    jwks_from_pem,
    load_key_from_material,
    sign_token,
    verify_token_with_key,
)

_INDEX_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>JWT Workbench</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body>
    <header>
      <h1>JWT Workbench</h1>
      <p>Offline JWT decode, verify, sign, and JWK tools.</p>
    </header>

    <main>
      <section class="panel">
        <h2>Encoded</h2>
        <textarea id="token" placeholder="Paste JWT here"></textarea>
        <div class="row">
          <button id="decode">Decode</button>
          <button id="verify">Verify</button>
          <button id="sign">Sign</button>
        </div>
        <div class="row">
          <label>Algorithm</label>
          <select id="alg">
            <option value="HS256">HS256</option>
            <option value="RS256">RS256</option>
            <option value="none">none (unsigned)</option>
          </select>
        </div>
      </section>

      <section class="panel">
        <h2>Decoded</h2>
        <label>Header</label>
        <textarea id="header" placeholder='{"alg":"HS256","typ":"JWT"}'></textarea>
        <label>Payload</label>
        <textarea
          id="payload"
          placeholder='{"sub":"1234567890","name":"John Doe","iat":1516239022}'
        ></textarea>
        <div class="row">
          <label>Warnings</label>
          <ul id="warnings"></ul>
        </div>
      </section>

      <section class="panel">
        <h2>Signature</h2>
        <div class="row">
          <label>Key type</label>
          <select id="keyType">
            <option value="secret">HMAC secret</option>
            <option value="pem">PEM (public/private)</option>
            <option value="jwk">JWK</option>
            <option value="jwks">JWKS</option>
          </select>
        </div>
        <textarea id="key" placeholder="Paste secret or key material"></textarea>
        <label>Key ID (kid)</label>
        <input id="kid" placeholder="Optional kid for JWKS" />
        <div class="row">
          <button id="convertJwk">Convert PEM → JWK</button>
          <button id="convertJwks">Convert PEM → JWKS</button>
        </div>
        <label>JWK/JWKS Output</label>
        <textarea id="jwkOutput" readonly></textarea>
      </section>
    </main>

    <footer>
      <p>JWT Workbench: jwt.io-style offline tooling with claim warnings.</p>
    </footer>

    <script src="/app.js"></script>
  </body>
</html>
"""


_APP_JS = """
const tokenEl = document.getElementById('token');
const headerEl = document.getElementById('header');
const payloadEl = document.getElementById('payload');
const warningsEl = document.getElementById('warnings');
const keyEl = document.getElementById('key');
const algEl = document.getElementById('alg');
const keyTypeEl = document.getElementById('keyType');
const kidEl = document.getElementById('kid');
const jwkOutputEl = document.getElementById('jwkOutput');

const setWarnings = (warnings) => {
  warningsEl.innerHTML = '';
  warnings.forEach((warning) => {
    const li = document.createElement('li');
    li.textContent = warning;
    warningsEl.appendChild(li);
  });
};

const prettyJson = (value) => {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch (err) {
    return value;
  }
};

const request = async (path, body) => {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || 'Request failed');
  }
  return payload;
};

const decode = async () => {
  const token = tokenEl.value.trim();
  if (!token) {
    return;
  }
  const data = await request('/api/decode', { token });
  headerEl.value = JSON.stringify(data.header, null, 2);
  payloadEl.value = JSON.stringify(data.payload, null, 2);
  setWarnings(data.warnings || []);
};

const verify = async () => {
  const token = tokenEl.value.trim();
  if (!token) {
    return;
  }
  const data = await request('/api/verify', {
    token,
    alg: algEl.value,
    key_type: keyTypeEl.value,
    key_text: keyEl.value,
    kid: kidEl.value || null,
  });
  headerEl.value = JSON.stringify(data.header, null, 2);
  payloadEl.value = JSON.stringify(data.payload, null, 2);
  setWarnings(data.warnings || []);
};

const sign = async () => {
  const payloadText = prettyJson(payloadEl.value.trim());
  const headerText = prettyJson(headerEl.value.trim());
  if (!payloadText) {
    return;
  }
  const data = await request('/api/sign', {
    payload: payloadText,
    header: headerText,
    alg: algEl.value,
    key_type: keyTypeEl.value,
    key_text: keyEl.value,
    kid: kidEl.value || null,
  });
  tokenEl.value = data.token;
  setWarnings(data.warnings || []);
};

const convertJwk = async () => {
  const data = await request('/api/jwk', {
    pem: keyEl.value,
    kid: kidEl.value || null,
  });
  jwkOutputEl.value = JSON.stringify(data.jwk, null, 2);
};

const convertJwks = async () => {
  const data = await request('/api/jwks', {
    pem: keyEl.value,
    kid: kidEl.value || null,
  });
  jwkOutputEl.value = JSON.stringify(data.jwks, null, 2);
};

['decode', 'verify', 'sign'].forEach((id) => {
  document.getElementById(id).addEventListener('click', async () => {
    try {
      if (id === 'decode') {
        await decode();
      } else if (id === 'verify') {
        await verify();
      } else {
        await sign();
      }
    } catch (err) {
      alert(err.message);
    }
  });
});

['convertJwk', 'convertJwks'].forEach((id) => {
  document.getElementById(id).addEventListener('click', async () => {
    try {
      if (id === 'convertJwk') {
        await convertJwk();
      } else {
        await convertJwks();
      }
    } catch (err) {
      alert(err.message);
    }
  });
});
"""


_STYLES = """
:root {
  color-scheme: light dark;
  font-family: "Inter", system-ui, sans-serif;
  --bg: #0f172a;
  --panel: #111827;
  --text: #e5e7eb;
  --muted: #94a3b8;
  --accent: #38bdf8;
}

body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--text);
}

header {
  padding: 32px 24px 0;
}

header h1 {
  margin: 0 0 8px;
  font-size: 2rem;
}

header p {
  margin: 0 0 24px;
  color: var(--muted);
}

main {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
  padding: 0 24px 24px;
}

.panel {
  background: var(--panel);
  padding: 16px;
  border-radius: 12px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 420px;
}

.panel h2 {
  margin: 0;
  font-size: 1.2rem;
}

textarea,
input,
select {
  width: 100%;
  padding: 10px;
  border-radius: 8px;
  border: 1px solid #1f2937;
  background: #0b1220;
  color: var(--text);
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
    "Liberation Mono", "Courier New", monospace;
}

textarea {
  min-height: 140px;
  resize: vertical;
}

button {
  background: var(--accent);
  color: #0f172a;
  border: none;
  border-radius: 8px;
  padding: 10px 16px;
  cursor: pointer;
  font-weight: 600;
}

button:hover {
  filter: brightness(1.05);
}

.row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.row > * {
  flex: 1;
}

#warnings {
  margin: 0;
  padding-left: 18px;
  color: #fbbf24;
}

footer {
  padding: 0 24px 24px;
  color: var(--muted);
}
"""


class JWTWorkbenchHandler(BaseHTTPRequestHandler):
    server_version = "JWTWorkbench/0.1"

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, text: str, content_type: str) -> None:
        data = text.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON payload") from exc
        if not isinstance(payload, dict):
            raise ValueError("JSON payload must be an object")
        return payload

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path == "/":
            self._send_text(_INDEX_HTML, "text/html; charset=utf-8")
            return
        if self.path == "/app.js":
            self._send_text(_APP_JS, "text/javascript; charset=utf-8")
            return
        if self.path == "/styles.css":
            self._send_text(_STYLES, "text/css; charset=utf-8")
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        try:
            payload = self._read_json()
            if self.path == "/api/decode":
                token = str(payload.get("token", "")).strip()
                if not token:
                    raise ValueError("token is required")
                header, data = decode_token(token)
                warnings = analyze_claims(data, header)
                self._send_json({"header": header, "payload": data, "warnings": warnings})
                return
            if self.path == "/api/verify":
                token = str(payload.get("token", "")).strip()
                key_type = str(payload.get("key_type", "secret"))
                key_text = str(payload.get("key_text", ""))
                alg = payload.get("alg") or None
                kid = payload.get("kid")
                if not token:
                    raise ValueError("token is required")
                if not key_text:
                    raise ValueError("key material is required")
                if not alg:
                    header, _ = decode_token(token)
                    alg = header.get("alg")
                if not alg:
                    raise ValueError("missing alg in header; supply alg")
                key = load_key_from_material(key_text, str(alg), key_type, kid=kid)
                header, data = verify_token_with_key(token, key=key, alg=alg)
                hmac_len = infer_hmac_key_len(None, key_text) if key_type == "secret" else None
                warnings = analyze_claims(data, header, hmac_key_len=hmac_len)
                self._send_json({"header": header, "payload": data, "warnings": warnings})
                return
            if self.path == "/api/sign":
                payload_text = payload.get("payload")
                header_text = payload.get("header")
                alg = str(payload.get("alg", "HS256"))
                key_type = str(payload.get("key_type", "secret"))
                key_text = str(payload.get("key_text", ""))
                kid = payload.get("kid")
                if key_type not in {"secret", "pem"}:
                    raise ValueError("signing requires secret or PEM key")
                if not key_text:
                    raise ValueError("key material is required")
                if payload_text is None:
                    raise ValueError("payload is required")
                payload_data = json.loads(str(payload_text))
                if not isinstance(payload_data, dict):
                    raise ValueError("payload must be a JSON object")
                if header_text:
                    header_data = json.loads(str(header_text))
                    if not isinstance(header_data, dict):
                        raise ValueError("header must be a JSON object")
                    header_data = {k: v for k, v in header_data.items() if k not in {"alg", "kid"}}
                else:
                    header_data = {}
                token = sign_token(
                    payload=payload_data,
                    key_path=None,
                    key_text=key_text,
                    alg=alg,
                    kid=str(kid) if kid else None,
                    headers=header_data or None,
                )
                header, decoded = decode_token(token)
                warnings = analyze_claims(decoded, header)
                self._send_json({"token": token, "warnings": warnings})
                return
            if self.path == "/api/jwk":
                pem_text = str(payload.get("pem", ""))
                if not pem_text:
                    raise ValueError("PEM is required")
                jwk = jwk_from_pem(
                    pem_text,
                    kid=str(payload.get("kid")) if payload.get("kid") else None,
                )
                self._send_json({"jwk": jwk})
                return
            if self.path == "/api/jwks":
                pem_text = str(payload.get("pem", ""))
                if not pem_text:
                    raise ValueError("PEM is required")
                jwks = jwks_from_pem(
                    pem_text,
                    kid=str(payload.get("kid")) if payload.get("kid") else None,
                )
                self._send_json({"jwks": jwks})
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), JWTWorkbenchHandler)
    print(f"JWT Workbench web UI running on http://{host}:{port}")
    server.serve_forever()
