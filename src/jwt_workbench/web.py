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
    <header class="site-header">
      <div class="container header-content">
        <div>
          <p class="eyebrow">JWT Workbench</p>
          <h1>Modern JWT tooling, kept offline.</h1>
          <p class="subtitle">Decode, verify, sign, and convert keys with a clean, focused UI.</p>
        </div>
        <div class="status-chip">Local only · No data leaves your device</div>
      </div>
    </header>

    <main class="container panels">
      <section class="panel">
        <div class="panel-header">
          <h2>Encoded</h2>
          <span class="panel-meta">Input</span>
        </div>
        <label for="token">JWT</label>
        <textarea
          id="token"
          placeholder="Paste JWT here"
          spellcheck="false"
          autocapitalize="off"
          autocomplete="off"
        ></textarea>
        <p id="status" class="status" role="status" aria-live="polite"></p>
        <div class="toolbar">
          <button id="decode" type="button">Decode</button>
          <button id="verify" type="button">Verify</button>
          <button id="sign" type="button">Sign</button>
          <button id="copyToken" class="ghost" type="button" aria-label="Copy JWT">Copy</button>
        </div>
        <div class="row">
          <label for="alg">Algorithm</label>
          <select id="alg">
            <option value="HS256">HS256</option>
            <option value="RS256">RS256</option>
            <option value="none">none (unsigned)</option>
          </select>
        </div>
        <div class="policy">
          <div class="row">
            <label for="aud">Expected aud</label>
            <input id="aud" placeholder="Optional audience" spellcheck="false" autocapitalize="off" />
          </div>
          <div class="row">
            <label for="iss">Expected iss</label>
            <input id="iss" placeholder="Optional issuer" spellcheck="false" autocapitalize="off" />
          </div>
          <div class="row">
            <label for="leeway">Clock skew (s)</label>
            <input id="leeway" inputmode="numeric" pattern="[0-9]*" placeholder="0" />
          </div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Decoded</h2>
          <span class="panel-meta">Inspect</span>
        </div>
        <label for="header">Header</label>
        <textarea
          id="header"
          placeholder='{"alg":"HS256","typ":"JWT"}'
          spellcheck="false"
          autocapitalize="off"
        ></textarea>
        <label for="payload">Payload</label>
        <textarea
          id="payload"
          placeholder='{"sub":"1234567890","name":"John Doe","iat":1516239022}'
          spellcheck="false"
          autocapitalize="off"
        ></textarea>
        <div class="row">
          <label>Warnings</label>
          <ul id="warnings"></ul>
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Signature</h2>
          <span class="panel-meta">Keys</span>
        </div>
        <div class="row">
          <label for="keyType">Key type</label>
          <select id="keyType">
            <option value="secret">HMAC secret</option>
            <option value="pem">PEM (public/private)</option>
            <option value="jwk">JWK</option>
            <option value="jwks">JWKS</option>
          </select>
        </div>
        <label for="key">Key material</label>
        <textarea
          id="key"
          placeholder="Paste secret or key material"
          spellcheck="false"
          autocapitalize="off"
        ></textarea>
        <label for="kid">Key ID (kid)</label>
        <input id="kid" placeholder="Optional kid for JWKS" spellcheck="false" autocapitalize="off" />
        <div class="toolbar secondary">
          <button id="convertJwk" class="ghost" type="button">Convert PEM → JWK</button>
          <button id="convertJwks" class="ghost" type="button">Convert PEM → JWKS</button>
        </div>
        <div class="output-header">
          <label for="jwkOutput">JWK/JWKS Output</label>
          <button
            id="copyJwkOutput"
            class="ghost"
            type="button"
            aria-label="Copy JWK or JWKS output"
          >
            Copy
          </button>
        </div>
        <textarea id="jwkOutput" readonly aria-label="JWK/JWKS output" spellcheck="false"></textarea>
      </section>
    </main>

    <footer class="site-footer">
      <div class="container">
        <p>JWT Workbench: jwt.io-style offline tooling with claim warnings.</p>
      </div>
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
const statusEl = document.getElementById('status');
const keyEl = document.getElementById('key');
const algEl = document.getElementById('alg');
const keyTypeEl = document.getElementById('keyType');
const kidEl = document.getElementById('kid');
const jwkOutputEl = document.getElementById('jwkOutput');
const audEl = document.getElementById('aud');
const issEl = document.getElementById('iss');
const leewayEl = document.getElementById('leeway');
const copyTokenEl = document.getElementById('copyToken');
const copyJwkOutputEl = document.getElementById('copyJwkOutput');

const actionButtonIds = [
  'decode',
  'verify',
  'sign',
  'copyToken',
  'convertJwk',
  'convertJwks',
  'copyJwkOutput',
];
const actionButtons = actionButtonIds
  .map((id) => document.getElementById(id))
  .filter((el) => Boolean(el));

const setBusy = (busy) => {
  actionButtons.forEach((button) => {
    button.disabled = Boolean(busy);
  });
};

const setStatus = (message, kind) => {
  statusEl.textContent = message || '';
  statusEl.dataset.kind = kind || '';
};

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

  const contentType = response.headers.get('content-type') || '';
  let payload = {};
  if (contentType.includes('application/json')) {
    payload = await response.json();
  } else {
    payload = { error: await response.text() };
  }

  if (!response.ok) {
    throw new Error(payload.error || `Request failed (${response.status})`);
  }
  return payload;
};

const copyText = async (value) => {
  const text = (value || '').toString();
  if (!text.trim()) {
    throw new Error('Nothing to copy');
  }
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const temp = document.createElement('textarea');
  temp.value = text;
  temp.setAttribute('readonly', 'true');
  temp.style.position = 'fixed';
  temp.style.left = '-9999px';
  document.body.appendChild(temp);
  temp.select();
  const ok = document.execCommand('copy');
  document.body.removeChild(temp);
  if (!ok) {
    throw new Error('Copy failed');
  }
};

const decode = async () => {
  const token = tokenEl.value.trim();
  if (!token) {
    return;
  }
  setStatus('', '');
  const data = await request('/api/decode', { token });
  headerEl.value = JSON.stringify(data.header, null, 2);
  payloadEl.value = JSON.stringify(data.payload, null, 2);
  setWarnings(data.warnings || []);
  setStatus('Decoded', 'ok');
};

const verify = async () => {
  const token = tokenEl.value.trim();
  if (!token) {
    return;
  }
  setStatus('', '');

  const leewayRaw = (leewayEl.value || '').trim();
  const leeway = leewayRaw === '' ? 0 : Number.parseInt(leewayRaw, 10);
  if (!Number.isFinite(leeway) || leeway < 0) {
    throw new Error('Clock skew must be a non-negative integer');
  }

  const data = await request('/api/verify', {
    token,
    alg: algEl.value,
    key_type: keyTypeEl.value,
    key_text: keyEl.value,
    kid: kidEl.value || null,
    aud: (audEl.value || '').trim() || null,
    iss: (issEl.value || '').trim() || null,
    leeway,
  });
  headerEl.value = JSON.stringify(data.header, null, 2);
  payloadEl.value = JSON.stringify(data.payload, null, 2);
  setWarnings(data.warnings || []);
  setStatus('Verified', 'ok');
};

const sign = async () => {
  const payloadText = prettyJson(payloadEl.value.trim());
  const headerText = prettyJson(headerEl.value.trim());
  if (!payloadText) {
    return;
  }
  setStatus('', '');
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
  setStatus('Signed', 'ok');
};

const convertJwk = async () => {
  setStatus('', '');
  const data = await request('/api/jwk', {
    pem: keyEl.value,
    kid: kidEl.value || null,
  });
  jwkOutputEl.value = JSON.stringify(data.jwk, null, 2);
  setStatus('Converted PEM → JWK', 'ok');
};

const convertJwks = async () => {
  setStatus('', '');
  const data = await request('/api/jwks', {
    pem: keyEl.value,
    kid: kidEl.value || null,
  });
  jwkOutputEl.value = JSON.stringify(data.jwks, null, 2);
  setStatus('Converted PEM → JWKS', 'ok');
};

const runAction = async (fn) => {
  try {
    setBusy(true);
    await fn();
  } catch (err) {
    setStatus(err.message || 'Request failed', 'error');
  } finally {
    setBusy(false);
  }
};

document.getElementById('decode').addEventListener('click', async () => {
  await runAction(decode);
});
document.getElementById('verify').addEventListener('click', async () => {
  await runAction(verify);
});
document.getElementById('sign').addEventListener('click', async () => {
  await runAction(sign);
});

document.getElementById('convertJwk').addEventListener('click', async () => {
  await runAction(convertJwk);
});
document.getElementById('convertJwks').addEventListener('click', async () => {
  await runAction(convertJwks);
});

copyTokenEl.addEventListener('click', async () => {
  await runAction(async () => {
    await copyText(tokenEl.value);
    setStatus('Copied JWT', 'ok');
  });
});

copyJwkOutputEl.addEventListener('click', async () => {
  await runAction(async () => {
    await copyText(jwkOutputEl.value);
    setStatus('Copied output', 'ok');
  });
});

document.addEventListener('keydown', async (event) => {
  const cmdOrCtrl = event.metaKey || event.ctrlKey;
  if (!cmdOrCtrl || event.key !== 'Enter') {
    return;
  }
  event.preventDefault();
  if (event.shiftKey) {
    await runAction(sign);
  } else {
    await runAction(verify);
  }
});
"""


_STYLES = """
:root {
  color-scheme: light dark;
  font-family: "SF Pro Text", "SF Pro Display", -apple-system, BlinkMacSystemFont, "Inter",
    system-ui, sans-serif;
  --bg: #0b0f1a;
  --bg-glow: radial-gradient(circle at top, rgba(56, 189, 248, 0.18), transparent 45%);
  --panel: rgba(17, 24, 39, 0.7);
  --panel-border: rgba(148, 163, 184, 0.12);
  --text: #f8fafc;
  --muted: rgba(226, 232, 240, 0.7);
  --accent-strong: #38bdf8;
  --input-bg: rgba(15, 23, 42, 0.65);
  --input-border: rgba(148, 163, 184, 0.2);
  --ghost-border: rgba(148, 163, 184, 0.4);
  --shadow: 0 20px 50px rgba(15, 23, 42, 0.35);
  --ok: rgba(34, 197, 94, 0.95);
  --error: rgba(248, 113, 113, 0.95);
  --warning: #fbbf24;
}

@media (prefers-color-scheme: light) {
  :root {
    --bg: #f7f8fb;
    --bg-glow: radial-gradient(circle at top, rgba(56, 189, 248, 0.15), transparent 45%);
    --panel: rgba(255, 255, 255, 0.75);
    --panel-border: rgba(15, 23, 42, 0.1);
    --text: #0b1220;
    --muted: rgba(15, 23, 42, 0.65);
    --input-bg: rgba(255, 255, 255, 0.9);
    --input-border: rgba(15, 23, 42, 0.14);
    --ghost-border: rgba(15, 23, 42, 0.22);
    --shadow: 0 20px 50px rgba(15, 23, 42, 0.08);
  }
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  background-image: var(--bg-glow);
}

.container {
  width: min(1100px, 100%);
  margin: 0 auto;
  padding: 0 24px;
}

.site-header {
  padding: 48px 0 16px;
}

.header-content {
  display: flex;
  flex-wrap: wrap;
  gap: 24px;
  align-items: center;
  justify-content: space-between;
}

.eyebrow {
  text-transform: uppercase;
  letter-spacing: 0.2em;
  font-size: 0.7rem;
  color: var(--muted);
  margin: 0 0 12px;
}

.site-header h1 {
  margin: 0 0 12px;
  font-size: clamp(2rem, 3vw, 2.6rem);
  font-weight: 600;
}

.subtitle {
  margin: 0;
  color: var(--muted);
  font-size: 1rem;
  max-width: 520px;
}

.status-chip {
  border-radius: 999px;
  padding: 8px 16px;
  border: 1px solid var(--panel-border);
  background: rgba(15, 23, 42, 0.06);
  font-size: 0.85rem;
  color: var(--muted);
  white-space: nowrap;
}

.panels {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 20px;
  padding: 16px 0 32px;
}

.panel {
  background: var(--panel);
  padding: 20px;
  border-radius: 18px;
  border: 1px solid var(--panel-border);
  box-shadow: var(--shadow);
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 420px;
  backdrop-filter: blur(12px);
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
}

.panel h2 {
  margin: 0;
  font-size: 1.1rem;
  font-weight: 600;
}

.panel-meta {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--muted);
}

label {
  display: block;
  color: var(--muted);
  font-size: 0.85rem;
}

textarea,
input,
select {
  width: 100%;
  padding: 10px 12px;
  border-radius: 12px;
  border: 1px solid var(--input-border);
  background: var(--input-bg);
  color: var(--text);
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
    "Liberation Mono", "Courier New", monospace;
  transition: border 0.2s ease, box-shadow 0.2s ease;
}

textarea:focus,
input:focus,
select:focus {
  outline: none;
  border-color: rgba(56, 189, 248, 0.5);
  box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
}

textarea {
  min-height: 140px;
  resize: vertical;
}

.output-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.output-header button {
  white-space: nowrap;
}

.status {
  margin: 0;
  min-height: 1.4em;
  color: var(--muted);
  font-size: 0.9rem;
}

.status[data-kind="ok"] {
  color: var(--ok);
}

.status[data-kind="error"] {
  color: var(--error);
}

button {
  background: var(--accent-strong);
  color: #0b0f1a;
  border: none;
  border-radius: 999px;
  padding: 10px 18px;
  cursor: pointer;
  font-weight: 600;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  box-shadow: 0 10px 20px rgba(56, 189, 248, 0.2);
}

button:hover {
  transform: translateY(-1px);
}

button:active {
  transform: translateY(0);
}

button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

button.ghost {
  background: transparent;
  color: var(--text);
  border: 1px solid var(--ghost-border);
  box-shadow: none;
}

.toolbar,
.row {
  display: flex;
  gap: 10px;
  align-items: center;
}

.toolbar {
  flex-wrap: wrap;
}

.policy {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.toolbar.secondary {
  flex-wrap: wrap;
}

.row > * {
  flex: 1;
}

#warnings {
  margin: 0;
  padding-left: 18px;
  color: var(--warning);
}

.site-footer {
  padding: 0 0 32px;
  color: var(--muted);
  font-size: 0.9rem;
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
                aud = payload.get("aud")
                iss = payload.get("iss")
                leeway = payload.get("leeway", 0)
                if not token:
                    raise ValueError("token is required")
                if not key_text:
                    raise ValueError("key material is required")
                if not alg:
                    header, _ = decode_token(token)
                    alg = header.get("alg")
                if not alg:
                    raise ValueError("missing alg in header; supply alg")
                if aud is not None and not isinstance(aud, str):
                    raise ValueError("aud must be a string")
                if iss is not None and not isinstance(iss, str):
                    raise ValueError("iss must be a string")
                if not isinstance(leeway, int) or leeway < 0:
                    raise ValueError("leeway must be a non-negative integer")
                key = load_key_from_material(key_text, str(alg), key_type, kid=kid)
                header, data = verify_token_with_key(
                    token,
                    key=key,
                    alg=alg,
                    audience=aud or None,
                    issuer=iss or None,
                    leeway=leeway,
                )
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
