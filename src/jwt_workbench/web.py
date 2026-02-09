from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from jwt import exceptions as jwt_exceptions

from .core import (
    analyze_claims,
    decode_token,
    format_jwt_error,
    infer_hmac_key_len,
    jwk_from_pem,
    jwks_from_pem,
    load_key_from_material,
    sign_token,
    verify_token_with_key,
)
from .samples import (
    SUPPORTED_KEY_PRESET_KINDS,
    SUPPORTED_SAMPLE_KINDS,
    generate_key_preset,
    generate_sample,
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
      <div class="container">
        <div class="header-content">
          <div>
            <p class="eyebrow">Offline toolkit</p>
            <h1>JWT Workbench</h1>
            <p class="subtitle">Offline JWT decode, verify, sign, and JWK tooling with claim warnings.</p>
          </div>
          <div class="status-chip">No network required</div>
        </div>
      </div>
    </header>

    <main class="container panels">
      <section class="panel">
        <div class="panel-header">
          <div>
            <h2>Encoded</h2>
            <span class="panel-meta">Input</span>
          </div>
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
          <button id="clearAll" class="ghost" type="button" aria-label="Clear all fields">Clear</button>
          <select id="sampleKind" aria-label="Sample preset">
            <option value="hs256">Sample HS256</option>
            <option value="rs256-pem">Sample RS256 (PEM)</option>
            <option value="rs256-jwks">Sample RS256 (JWKS)</option>
            <option value="es256-pem">Sample ES256 (PEM)</option>
            <option value="eddsa-pem">Sample EdDSA (PEM)</option>
            <option value="none">Sample none</option>
          </select>
          <button id="loadSample" class="ghost" type="button">Load</button>
        </div>
        <div class="row">
          <label for="alg">Algorithm</label>
          <select id="alg">
            <option value="HS256">HS256</option>
            <option value="RS256">RS256</option>
            <option value="ES256">ES256</option>
            <option value="EdDSA">EdDSA</option>
            <option value="none">none (unsigned)</option>
          </select>
        </div>
        <div class="policy">
          <div class="row">
            <label for="policyProfile">Policy profile</label>
            <select id="policyProfile" aria-label="Verification policy profile">
              <option value="legacy">legacy (require nothing)</option>
              <option value="default">default (require exp)</option>
              <option value="strict">strict (require exp,aud,iss)</option>
            </select>
          </div>
          <div class="row">
            <label for="aud">Expected aud</label>
            <input
              id="aud"
              placeholder="Comma-separated allowlist"
              spellcheck="false"
              autocapitalize="off"
            />
          </div>
          <div class="row">
            <label for="iss">Expected iss</label>
            <input
              id="iss"
              placeholder="Comma-separated allowlist"
              spellcheck="false"
              autocapitalize="off"
            />
          </div>
          <div class="row">
            <label for="leeway">Clock skew (s)</label>
            <input id="leeway" inputmode="numeric" pattern="[0-9]*" placeholder="0" />
          </div>
          <div class="row">
            <label for="requireClaims">Required claims</label>
            <input
              id="requireClaims"
              placeholder="Comma-separated (exp,aud,iss)"
              spellcheck="false"
              autocapitalize="off"
            />
          </div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <div>
            <h2>Decoded</h2>
            <span class="panel-meta">Inspect</span>
          </div>
        </div>
        <div class="output-header">
          <label for="header">Header</label>
          <button id="formatHeader" class="ghost" type="button" aria-label="Format header JSON">
            Format
          </button>
        </div>
        <textarea
          id="header"
          placeholder='{"alg":"HS256","typ":"JWT"}'
          spellcheck="false"
          autocapitalize="off"
        ></textarea>
        <div class="output-header">
          <label for="payload">Payload</label>
          <button id="formatPayload" class="ghost" type="button" aria-label="Format payload JSON">
            Format
          </button>
        </div>
        <textarea
          id="payload"
          placeholder='{"sub":"1234567890","name":"Ada Lovelace","iat":1516239022}'
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
          <div>
            <h2>Keys</h2>
            <span class="panel-meta">Material</span>
          </div>
        </div>
        <div class="tabs" role="tablist" aria-label="Key type">
          <button class="tab" type="button" data-keytype="secret" aria-selected="true">HMAC</button>
          <button class="tab" type="button" data-keytype="pem" aria-selected="false">PEM</button>
          <button class="tab" type="button" data-keytype="jwk" aria-selected="false">JWK</button>
          <button class="tab" type="button" data-keytype="jwks" aria-selected="false">JWKS</button>
        </div>
        <label class="sr-only" for="keyType">Key type</label>
        <select id="keyType" class="sr-only">
          <option value="secret">HMAC secret</option>
          <option value="pem">PEM (public/private)</option>
          <option value="jwk">JWK</option>
          <option value="jwks">JWKS</option>
        </select>
        <div class="row preset-row">
          <label for="keyPreset">Key presets</label>
          <div class="row-inline">
            <select id="keyPreset"></select>
            <button id="loadPreset" class="ghost" type="button">Load</button>
          </div>
        </div>
        <div class="output-header">
          <label for="key">Key material</label>
          <button id="formatKey" class="ghost" type="button" aria-label="Format key JSON">Format</button>
        </div>
        <textarea
          id="key"
          placeholder="Paste secret or key material"
          spellcheck="false"
          autocapitalize="off"
        ></textarea>
        <div class="row">
          <label for="kid">Key ID (kid)</label>
          <input id="kid" placeholder="Optional kid for JWKS" spellcheck="false" autocapitalize="off" />
        </div>
        <div id="jwksPicker" class="jwks-picker" hidden>
          <label for="kidSelect">JWKS keys</label>
          <select id="kidSelect"></select>
        </div>
        <div id="jwksViewer" class="jwks-viewer" hidden>
          <div class="output-header">
            <label>JWKS viewer</label>
            <span id="jwksSummary" class="meta"></span>
          </div>
          <ul id="jwksList"></ul>
        </div>
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

    <footer class="container footer">
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
const statusEl = document.getElementById('status');
const keyEl = document.getElementById('key');
const algEl = document.getElementById('alg');
const keyTypeEl = document.getElementById('keyType');
const kidEl = document.getElementById('kid');
const jwkOutputEl = document.getElementById('jwkOutput');
const audEl = document.getElementById('aud');
const issEl = document.getElementById('iss');
const policyProfileEl = document.getElementById('policyProfile');
const leewayEl = document.getElementById('leeway');
const requireClaimsEl = document.getElementById('requireClaims');
const copyTokenEl = document.getElementById('copyToken');
const copyJwkOutputEl = document.getElementById('copyJwkOutput');
const formatHeaderEl = document.getElementById('formatHeader');
const formatPayloadEl = document.getElementById('formatPayload');
const formatKeyEl = document.getElementById('formatKey');
const convertJwkEl = document.getElementById('convertJwk');
const convertJwksEl = document.getElementById('convertJwks');
const jwksPickerEl = document.getElementById('jwksPicker');
const kidSelectEl = document.getElementById('kidSelect');
const jwksViewerEl = document.getElementById('jwksViewer');
const jwksListEl = document.getElementById('jwksList');
const jwksSummaryEl = document.getElementById('jwksSummary');
const clearAllEl = document.getElementById('clearAll');
const sampleKindEl = document.getElementById('sampleKind');
const loadSampleEl = document.getElementById('loadSample');
const keyPresetEl = document.getElementById('keyPreset');
const loadPresetEl = document.getElementById('loadPreset');
const keyTabs = Array.from(document.querySelectorAll('[data-keytype]'));

const KEY_PRESETS = {
  secret: [
    {
      id: 'secret-demo',
      label: 'Demo secret (short)',
      kind: 'static',
      value: 'demo-secret-please-change',
      alg: 'HS256',
    },
    {
      id: 'secret-strong',
      label: 'Demo secret (32+ bytes)',
      kind: 'static',
      value: 'correct-horse-battery-staple-please-change-2026',
      alg: 'HS256',
    },
  ],
  pem: [
    {
      id: 'pem-private',
      label: 'Sample RSA private key',
      kind: 'api',
      apiKind: 'pem-private',
      alg: 'RS256',
    },
    {
      id: 'pem-public',
      label: 'Sample RSA public key',
      kind: 'api',
      apiKind: 'pem-public',
      alg: 'RS256',
    },
    {
      id: 'pem-ec-private',
      label: 'Sample EC P-256 private key',
      kind: 'api',
      apiKind: 'pem-ec-private',
      alg: 'ES256',
    },
    {
      id: 'pem-ec-public',
      label: 'Sample EC P-256 public key',
      kind: 'api',
      apiKind: 'pem-ec-public',
      alg: 'ES256',
    },
    {
      id: 'pem-ed25519-private',
      label: 'Sample Ed25519 private key',
      kind: 'api',
      apiKind: 'pem-ed25519-private',
      alg: 'EdDSA',
    },
    {
      id: 'pem-ed25519-public',
      label: 'Sample Ed25519 public key',
      kind: 'api',
      apiKind: 'pem-ed25519-public',
      alg: 'EdDSA',
    },
  ],
  jwk: [
    {
      id: 'jwk-sample',
      label: 'Sample RSA JWK',
      kind: 'api',
      apiKind: 'jwk',
      alg: 'RS256',
    },
    {
      id: 'jwk-ec-sample',
      label: 'Sample EC P-256 JWK',
      kind: 'api',
      apiKind: 'jwk-ec',
      alg: 'ES256',
    },
    {
      id: 'jwk-okp-sample',
      label: 'Sample Ed25519 OKP JWK',
      kind: 'api',
      apiKind: 'jwk-okp',
      alg: 'EdDSA',
    },
    {
      id: 'jwk-template',
      label: 'Template JWK',
      kind: 'static',
      value: '{\n  "kty": "RSA",\n  "kid": "demo-k1",\n  "use": "sig",\n  "alg": "RS256",\n  "n": "<modulus>",\n  "e": "AQAB"\n}',
      alg: 'RS256',
    },
    {
      id: 'jwk-ec-template',
      label: 'Template EC JWK',
      kind: 'static',
      value:
        '{\n  "kty": "EC",\n  "kid": "demo-ec1",\n  "use": "sig",\n  "alg": "ES256",\n  "crv": "P-256",\n  "x": "<x>",\n  "y": "<y>"\n}',
      alg: 'ES256',
    },
    {
      id: 'jwk-okp-template',
      label: 'Template OKP JWK',
      kind: 'static',
      value:
        '{\n  "kty": "OKP",\n  "kid": "demo-ed1",\n  "use": "sig",\n  "alg": "EdDSA",\n  "crv": "Ed25519",\n  "x": "<x>"\n}',
      alg: 'EdDSA',
    },
  ],
  jwks: [
    {
      id: 'jwks-sample',
      label: 'Sample JWKS (2 keys)',
      kind: 'api',
      apiKind: 'jwks',
      alg: 'RS256',
    },
    {
      id: 'jwks-ec-sample',
      label: 'Sample EC JWKS (2 keys)',
      kind: 'api',
      apiKind: 'jwks-ec',
      alg: 'ES256',
    },
    {
      id: 'jwks-okp-sample',
      label: 'Sample OKP JWKS (2 keys)',
      kind: 'api',
      apiKind: 'jwks-okp',
      alg: 'EdDSA',
    },
    {
      id: 'jwks-template',
      label: 'Template JWKS',
      kind: 'static',
      value: '{\n  "keys": [\n    {\n      "kty": "RSA",\n      "kid": "demo-k1",\n      "use": "sig",\n      "alg": "RS256",\n      "n": "<modulus>",\n      "e": "AQAB"\n    }\n  ]\n}',
      alg: 'RS256',
    },
    {
      id: 'jwks-ec-template',
      label: 'Template EC JWKS',
      kind: 'static',
      value:
        '{\n  "keys": [\n    {\n      "kty": "EC",\n      "kid": "demo-ec1",\n      "use": "sig",\n      "alg": "ES256",\n      "crv": "P-256",\n      "x": "<x>",\n      "y": "<y>"\n    }\n  ]\n}',
      alg: 'ES256',
    },
    {
      id: 'jwks-okp-template',
      label: 'Template OKP JWKS',
      kind: 'static',
      value:
        '{\n  "keys": [\n    {\n      "kty": "OKP",\n      "kid": "demo-ed1",\n      "use": "sig",\n      "alg": "EdDSA",\n      "crv": "Ed25519",\n      "x": "<x>"\n    }\n  ]\n}',
      alg: 'EdDSA',
    },
  ],
};

const actionButtonIds = [
  'decode',
  'verify',
  'sign',
  'copyToken',
  'clearAll',
  'loadSample',
  'loadPreset',
  'convertJwk',
  'convertJwks',
  'copyJwkOutput',
  'formatHeader',
  'formatPayload',
  'formatKey',
];
const actionButtons = actionButtonIds
  .map((id) => document.getElementById(id))
  .filter((el) => Boolean(el));

const POLICY_PROFILES = {
  legacy: { leeway: 0, require: [] },
  default: { leeway: 0, require: ['exp'] },
  strict: { leeway: 0, require: ['exp', 'aud', 'iss'] },
};

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

const parseJsonObject = (value, label) => {
  if (!value.trim()) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch (err) {
    throw new Error(`${label} must be valid JSON`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return parsed;
};

const formatJsonTextarea = (el, label) => {
  const obj = parseJsonObject(el.value, label);
  if (obj === null) {
    return;
  }
  el.value = JSON.stringify(obj, null, 2);
};

const parseListInput = (value) => {
  const trimmed = (value || '').trim();
  if (!trimmed) {
    return null;
  }
  const parts = trimmed.split(',').map((part) => part.trim()).filter((part) => part.length > 0);
  if (parts.length <= 1) {
    return parts[0] || null;
  }
  return parts;
};

const parseClaimRequirements = (value) => {
  const parsed = parseListInput(value);
  if (parsed === null) {
    return null;
  }
  if (typeof parsed === 'string') {
    return [parsed];
  }
  return Array.from(new Set(parsed));
};

const inferPolicyProfile = (requireClaims) => {
  if (!Array.isArray(requireClaims) || requireClaims.length === 0) {
    return 'legacy';
  }
  const normalized = Array.from(new Set(requireClaims.map((item) => String(item).trim()).filter(Boolean)));
  normalized.sort();
  if (normalized.length === 1 && normalized[0] === 'exp') {
    return 'default';
  }
  if (normalized.length === 3 && normalized.join(',') === 'aud,exp,iss') {
    return 'strict';
  }
  return 'legacy';
};

const applyPolicyProfile = () => {
  const selected = policyProfileEl.value || 'legacy';
  const profile = POLICY_PROFILES[selected] || POLICY_PROFILES.legacy;
  leewayEl.value = typeof profile.leeway === 'number' ? String(profile.leeway) : '';
  requireClaimsEl.value = Array.isArray(profile.require) ? profile.require.join(',') : '';
  setStatus(`Applied ${selected} policy`, 'ok');
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

  const aud = parseListInput(audEl.value);
  const iss = parseListInput(issEl.value);
  const requireClaims = parseClaimRequirements(requireClaimsEl.value);

  const data = await request('/api/verify', {
    token,
    alg: algEl.value,
    key_type: keyTypeEl.value,
    key_text: keyEl.value,
    kid: kidEl.value || null,
    aud,
    iss,
    leeway,
    require: requireClaims,
  });
  headerEl.value = JSON.stringify(data.header, null, 2);
  payloadEl.value = JSON.stringify(data.payload, null, 2);
  setWarnings(data.warnings || []);
  setStatus('Verified', 'ok');
};

const sign = async () => {
  const payloadObj = parseJsonObject(payloadEl.value, 'Payload');
  if (payloadObj === null) {
    return;
  }
  const headerObj = parseJsonObject(headerEl.value, 'Header');
  const payloadText = JSON.stringify(payloadObj, null, 2);
  const headerText = headerObj ? JSON.stringify(headerObj, null, 2) : '';
  setStatus('', '');
  const alg = algEl.value;
  const data = await request('/api/sign', {
    payload: payloadText,
    header: headerText,
    alg,
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

const setKeyType = (value) => {
  keyTypeEl.value = value;
  keyTabs.forEach((tab) => {
    const active = tab.dataset.keytype === value;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  renderPresetOptions();
  updateKeyUi();
  updateJwksPicker();
  updateJwksViewer();
};

const renderPresetOptions = () => {
  const keyType = keyTypeEl.value;
  const presets = KEY_PRESETS[keyType] || [];
  keyPresetEl.innerHTML = '';
  const placeholder = document.createElement('option');
  placeholder.value = '';
  placeholder.textContent = 'Choose preset...';
  keyPresetEl.appendChild(placeholder);
  presets.forEach((preset) => {
    const option = document.createElement('option');
    option.value = preset.id;
    option.textContent = preset.label;
    keyPresetEl.appendChild(option);
  });
  keyPresetEl.value = '';
};

const applyPreset = async () => {
  const keyType = keyTypeEl.value;
  const presetId = keyPresetEl.value;
  if (!presetId) {
    return;
  }
  const preset = (KEY_PRESETS[keyType] || []).find((item) => item.id === presetId);
  if (!preset) {
    return;
  }
  if (preset.kind === 'static') {
    keyEl.value = preset.value || '';
    if (preset.alg) {
      algEl.value = preset.alg;
    }
    setStatus('Loaded key preset', 'ok');
  } else if (preset.kind === 'api') {
    const data = await request('/api/key-preset', { kind: preset.apiKind });
    keyEl.value = data.key_text || '';
    if (data.kid) {
      kidEl.value = data.kid;
    }
    if (data.alg) {
      algEl.value = data.alg;
    }
    setStatus('Loaded key preset', 'ok');
  }
  keyPresetEl.value = '';
  updateKeyUi();
  updateJwksPicker();
  updateJwksViewer();
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

clearAllEl.addEventListener('click', async () => {
  await runAction(async () => {
    tokenEl.value = '';
    headerEl.value = '';
    payloadEl.value = '';
    keyEl.value = '';
    kidEl.value = '';
    jwkOutputEl.value = '';
    audEl.value = '';
    issEl.value = '';
    policyProfileEl.value = 'legacy';
    leewayEl.value = '';
    requireClaimsEl.value = '';
    setWarnings([]);
    setStatus('Cleared', 'ok');
    updateKeyUi();
    updateJwksPicker();
    updateJwksViewer();
  });
});

policyProfileEl.addEventListener('change', async () => {
  await runAction(async () => {
    applyPolicyProfile();
  });
});

loadSampleEl.addEventListener('click', async () => {
  await runAction(async () => {
    const data = await request('/api/sample', { kind: sampleKindEl.value });

    tokenEl.value = data.token || '';
    headerEl.value = JSON.stringify(data.header || {}, null, 2);
    payloadEl.value = JSON.stringify(data.payload || {}, null, 2);

    if (data.alg) {
      algEl.value = data.alg;
    }
    if (data.key_type) {
      setKeyType(data.key_type);
    }

    audEl.value = data.aud || '';
    issEl.value = data.iss || '';
    leewayEl.value = typeof data.leeway === 'number' ? String(data.leeway) : '';
    if (Array.isArray(data.require)) {
      requireClaimsEl.value = data.require.join(',');
      policyProfileEl.value = inferPolicyProfile(data.require);
    } else {
      requireClaimsEl.value = '';
      policyProfileEl.value = 'legacy';
    }

    keyEl.value = data.key_text || '';
    kidEl.value = data.kid || '';
    jwkOutputEl.value = '';

    setWarnings(data.warnings || []);
    setStatus('Loaded sample', 'ok');
    updateKeyUi();
    updateJwksPicker();
    updateJwksViewer();
  });
});

loadPresetEl.addEventListener('click', async () => {
  await runAction(applyPreset);
});

copyJwkOutputEl.addEventListener('click', async () => {
  await runAction(async () => {
    await copyText(jwkOutputEl.value);
    setStatus('Copied output', 'ok');
  });
});

const updateKeyUi = () => {
  const noneAlg = algEl.value === 'none';
  const keyType = keyTypeEl.value;
  keyTabs.forEach((tab) => {
    tab.disabled = noneAlg;
  });
  keyTypeEl.disabled = noneAlg;
  keyEl.disabled = noneAlg;
  kidEl.disabled = noneAlg;
  keyPresetEl.disabled = noneAlg;
  loadPresetEl.disabled = noneAlg;
  convertJwkEl.disabled = noneAlg || keyType !== 'pem';
  convertJwksEl.disabled = noneAlg || keyType !== 'pem';
  formatKeyEl.disabled = noneAlg || (keyType !== 'jwk' && keyType !== 'jwks');
  if (noneAlg) {
    keyEl.placeholder = 'No key required for alg=none';
    kidEl.placeholder = 'Not used for alg=none';
  } else {
    keyEl.placeholder = 'Paste secret or key material';
    kidEl.placeholder = 'Optional kid for JWKS';
  }

  jwksPickerEl.hidden = noneAlg || keyType !== 'jwks';
  jwksViewerEl.hidden = noneAlg || keyType !== 'jwks';
};

algEl.addEventListener('change', updateKeyUi);
keyTypeEl.addEventListener('change', () => setKeyType(keyTypeEl.value));
keyTabs.forEach((tab) => {
  tab.addEventListener('click', () => setKeyType(tab.dataset.keytype));
});

const updateJwksPicker = () => {
  if (jwksPickerEl.hidden) {
    return;
  }
  kidSelectEl.innerHTML = '';

  let jwks;
  try {
    jwks = JSON.parse(keyEl.value);
  } catch (err) {
    kidSelectEl.disabled = true;
    return;
  }

  const keys = jwks && typeof jwks === 'object' ? jwks.keys : null;
  if (!Array.isArray(keys) || keys.length === 0) {
    kidSelectEl.disabled = true;
    return;
  }

  const placeholder = document.createElement('option');
  placeholder.value = '';
  placeholder.textContent = keys.length === 1 ? 'Single key' : 'Select kid...';
  kidSelectEl.appendChild(placeholder);

  keys.forEach((key, index) => {
    const option = document.createElement('option');
    const kid = key && typeof key === 'object' ? key.kid : null;
    if (typeof kid === 'string' && kid.trim()) {
      option.value = kid;
      option.textContent = kid;
    } else {
      option.value = '';
      option.textContent = `Key ${index + 1} (no kid)`;
      option.disabled = true;
    }
    kidSelectEl.appendChild(option);
  });

  kidSelectEl.disabled = keys.length <= 1;
};

const updateJwksViewer = () => {
  jwksListEl.innerHTML = '';
  jwksSummaryEl.textContent = '';

  if (jwksViewerEl.hidden) {
    return;
  }

  let jwks;
  try {
    jwks = JSON.parse(keyEl.value);
  } catch (err) {
    jwksViewerEl.hidden = true;
    return;
  }

  const keys = jwks && typeof jwks === 'object' ? jwks.keys : null;
  if (!Array.isArray(keys) || keys.length === 0) {
    jwksViewerEl.hidden = true;
    return;
  }

  jwksViewerEl.hidden = false;
  jwksSummaryEl.textContent = `${keys.length} key${keys.length === 1 ? '' : 's'}`;

  keys.forEach((key, index) => {
    const li = document.createElement('li');
    const kid = key && typeof key === 'object' ? key.kid : null;
    const kty = key && typeof key === 'object' ? key.kty : null;
    const alg = key && typeof key === 'object' ? key.alg : null;
    const use = key && typeof key === 'object' ? key.use : null;

    const tag = document.createElement('span');
    tag.className = 'key-tag';
    tag.textContent = kid && typeof kid === 'string' ? kid : `Key ${index + 1}`;

    const meta = document.createElement('span');
    meta.className = 'meta';
    const metaParts = [kty, alg, use].filter((part) => typeof part === 'string' && part);
    meta.textContent = metaParts.join(' · ');

    li.appendChild(tag);
    li.appendChild(meta);
    jwksListEl.appendChild(li);
  });
};

keyEl.addEventListener('input', () => {
  updateJwksPicker();
  updateJwksViewer();
});
keyTypeEl.addEventListener('change', () => {
  updateJwksPicker();
  updateJwksViewer();
});

kidSelectEl.addEventListener('change', () => {
  const selected = kidSelectEl.value;
  if (!selected) {
    return;
  }
  kidEl.value = selected;
});

formatHeaderEl.addEventListener('click', async () => {
  await runAction(async () => {
    formatJsonTextarea(headerEl, 'Header');
    setStatus('Formatted header', 'ok');
  });
});

formatPayloadEl.addEventListener('click', async () => {
  await runAction(async () => {
    formatJsonTextarea(payloadEl, 'Payload');
    setStatus('Formatted payload', 'ok');
  });
});

formatKeyEl.addEventListener('click', async () => {
  await runAction(async () => {
    formatJsonTextarea(keyEl, 'Key');
    setStatus('Formatted key JSON', 'ok');
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

setKeyType('secret');
updateKeyUi();
updateJwksPicker();
updateJwksViewer();
policyProfileEl.value = 'legacy';
"""


_STYLES = """
:root {
  color-scheme: light dark;
  font-family: "Space Grotesk", "Avenir Next", "Segoe UI", sans-serif;
  --bg: #0b1118;
  --bg-glow: radial-gradient(circle at top, rgba(20, 184, 166, 0.22), transparent 45%),
    radial-gradient(circle at 20% 10%, rgba(245, 158, 11, 0.12), transparent 40%);
  --panel: rgba(17, 24, 39, 0.72);
  --panel-border: rgba(148, 163, 184, 0.16);
  --text: #f8fafc;
  --muted: rgba(226, 232, 240, 0.72);
  --accent: #14b8a6;
  --accent-strong: #f59e0b;
  --input-bg: rgba(15, 23, 42, 0.7);
  --input-border: rgba(148, 163, 184, 0.24);
  --ghost-border: rgba(148, 163, 184, 0.4);
  --shadow: 0 24px 50px rgba(5, 10, 18, 0.45);
  --ok: rgba(34, 197, 94, 0.95);
  --error: rgba(248, 113, 113, 0.95);
  --warning: #fbbf24;
}

@media (prefers-color-scheme: light) {
  :root {
    --bg: #f6f5f1;
    --bg-glow: radial-gradient(circle at top, rgba(20, 184, 166, 0.18), transparent 50%),
      radial-gradient(circle at 20% 20%, rgba(245, 158, 11, 0.12), transparent 50%);
    --panel: rgba(255, 255, 255, 0.88);
    --panel-border: rgba(15, 23, 42, 0.12);
    --text: #0b1220;
    --muted: rgba(15, 23, 42, 0.6);
    --input-bg: rgba(255, 255, 255, 0.95);
    --input-border: rgba(15, 23, 42, 0.16);
    --ghost-border: rgba(15, 23, 42, 0.25);
    --shadow: 0 24px 40px rgba(15, 23, 42, 0.08);
  }
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  padding: 0;
  min-height: 100vh;
  background: var(--bg);
  background-image: var(--bg-glow);
  color: var(--text);
}

.container {
  width: min(1120px, 100%);
  margin: 0 auto;
  padding: 0 24px;
}

.site-header {
  padding: 48px 0 24px;
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
  letter-spacing: 0.26em;
  font-size: 0.68rem;
  color: var(--muted);
  margin: 0 0 12px;
}

.site-header h1 {
  margin: 0 0 12px;
  font-size: clamp(2rem, 4vw, 2.8rem);
  font-weight: 600;
}

.subtitle {
  margin: 0;
  color: var(--muted);
  font-size: 1rem;
  max-width: 560px;
}

.status-chip {
  border-radius: 999px;
  padding: 8px 16px;
  border: 1px solid var(--panel-border);
  background: rgba(15, 23, 42, 0.16);
  font-size: 0.85rem;
  color: var(--muted);
  white-space: nowrap;
}

.panels {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 18px;
  padding-bottom: 24px;
}

.panel {
  background: var(--panel);
  padding: 18px;
  border-radius: 16px;
  border: 1px solid var(--panel-border);
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 420px;
  box-shadow: var(--shadow);
}

.panel-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.panel h2 {
  margin: 0;
  font-size: 1.1rem;
  font-weight: 600;
}

.panel-meta {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.16em;
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
  font-family: "IBM Plex Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo,
    Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
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

.output-header .meta {
  font-size: 0.8rem;
  color: var(--muted);
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
  background: var(--accent);
  color: #0b1220;
  border: none;
  border-radius: 10px;
  padding: 10px 16px;
  cursor: pointer;
  font-weight: 600;
  transition: transform 0.15s ease, filter 0.15s ease;
}

button:hover {
  transform: translateY(-1px);
  filter: brightness(1.05);
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
  gap: 8px;
  align-items: center;
}

.toolbar {
  flex-wrap: wrap;
}

.toolbar select {
  width: auto;
  flex: 1 1 180px;
}

.row > * {
  flex: 1;
}

.row-inline {
  display: flex;
  gap: 8px;
  flex: 2;
}

.row-inline select {
  flex: 1;
}

.policy {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.tabs {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.tab {
  background: transparent;
  border: 1px solid var(--ghost-border);
  color: var(--text);
  padding: 8px 14px;
  border-radius: 999px;
  font-size: 0.85rem;
}

.tab.active {
  background: rgba(20, 184, 166, 0.2);
  border-color: rgba(20, 184, 166, 0.6);
  color: var(--text);
}

.preset-row label {
  flex: 1;
}

.jwks-picker {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.jwks-viewer {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.jwks-viewer ul {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.jwks-viewer li {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 12px;
  border-radius: 10px;
  border: 1px solid var(--panel-border);
  background: rgba(15, 23, 42, 0.2);
}

.key-tag {
  font-size: 0.8rem;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--ghost-border);
  background: rgba(15, 23, 42, 0.3);
}

.meta {
  color: var(--muted);
  font-size: 0.8rem;
}

#warnings {
  margin: 0;
  padding-left: 18px;
  color: var(--warning);
}

.footer {
  padding-bottom: 32px;
  color: var(--muted);
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

@media (max-width: 768px) {
  .row,
  .toolbar {
    flex-direction: column;
    align-items: stretch;
  }

  .row-inline {
    flex-direction: column;
  }
}
"""


class JWTWorkbenchHandler(BaseHTTPRequestHandler):
    server_version = "JWTWorkbench/0.1"
    _MAX_BODY_BYTES = 256 * 1024

    def _send_common_headers(self, content_type: str, content_length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self._send_common_headers("application/json", len(data))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, text: str, content_type: str) -> None:
        data = text.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self._send_common_headers(content_type, len(data))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            raise ValueError("Content-Type must be application/json")
        length_raw = self.headers.get("Content-Length")
        if length_raw is None:
            raise ValueError("Content-Length is required")
        try:
            length = int(length_raw)
        except ValueError as exc:
            raise ValueError("invalid Content-Length header") from exc
        if length <= 0:
            raise ValueError("request body is required")
        if length > self._MAX_BODY_BYTES:
            raise ValueError("request body too large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("incomplete request body")
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
        self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        try:
            payload = self._read_json()
            if self.path == "/api/sample":
                kind = str(payload.get("kind", "")).strip()
                if kind not in SUPPORTED_SAMPLE_KINDS:
                    raise ValueError("unknown sample kind")
                sample = generate_sample(kind)
                self._send_json(
                    {
                        "token": sample["token"],
                        "header": sample["header"],
                        "payload": sample["payload"],
                        "warnings": sample["warnings"],
                        "alg": sample["alg"],
                        "key_type": sample["key_type"],
                        "key_text": sample["key_text"],
                        "kid": sample["kid"],
                        "aud": sample["aud"],
                        "iss": sample["iss"],
                        "leeway": sample["leeway"],
                        "require": sample["require"],
                    }
                )
                return
            if self.path == "/api/key-preset":
                kind = str(payload.get("kind", "")).strip()
                if kind not in SUPPORTED_KEY_PRESET_KINDS:
                    raise ValueError("unknown key preset")
                self._send_json(generate_key_preset(kind))
                return
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
                required_claims = payload.get("require")
                leeway = payload.get("leeway", 0)
                if not token:
                    raise ValueError("token is required")
                if key_type not in {"secret", "pem", "jwk", "jwks"}:
                    raise ValueError("key_type must be one of: secret, pem, jwk, jwks")
                if not key_text:
                    raise ValueError("key material is required")
                if not alg:
                    header, _ = decode_token(token)
                    alg = header.get("alg")
                if not alg:
                    raise ValueError("missing alg in header; supply alg")
                if aud is not None and not isinstance(aud, (str, list)):
                    raise ValueError("aud must be a string or list of strings")
                if isinstance(aud, list):
                    if not aud:
                        aud = None
                    elif not all(isinstance(item, str) for item in aud):
                        raise ValueError("aud must be a string or list of strings")
                    else:
                        aud = [item for item in aud if item.strip()]
                        if not aud:
                            aud = None
                if iss is not None and not isinstance(iss, (str, list)):
                    raise ValueError("iss must be a string or list of strings")
                if isinstance(iss, list):
                    if not iss:
                        iss = None
                    elif not all(isinstance(item, str) for item in iss):
                        raise ValueError("iss must be a string or list of strings")
                    else:
                        iss = [item for item in iss if item.strip()]
                        if not iss:
                            iss = None
                if isinstance(iss, str) and not iss.strip():
                    iss = None
                if required_claims is not None and not isinstance(required_claims, (str, list)):
                    raise ValueError("require must be a string or list of strings")
                if isinstance(required_claims, list):
                    if not required_claims:
                        required_claims = None
                    elif not all(isinstance(item, str) for item in required_claims):
                        raise ValueError("require must be a string or list of strings")
                    else:
                        required_claims = [item.strip() for item in required_claims if item.strip()]
                        if not required_claims:
                            required_claims = None
                if isinstance(required_claims, str) and not required_claims.strip():
                    required_claims = None
                if kid is not None and not isinstance(kid, str):
                    raise ValueError("kid must be a string")
                if isinstance(leeway, str) and leeway.strip().isdigit():
                    leeway = int(leeway)
                if not isinstance(leeway, int) or leeway < 0:
                    raise ValueError("leeway must be a non-negative integer")
                key = load_key_from_material(key_text, str(alg), key_type, kid=kid)
                try:
                    header, data = verify_token_with_key(
                        token,
                        key=key,
                        alg=alg,
                        audience=aud or None,
                        issuer=iss or None,
                        leeway=leeway,
                        required_claims=required_claims or None,
                    )
                except jwt_exceptions.PyJWTError as exc:
                    raise ValueError(
                        format_jwt_error(exc, audience=aud or None, issuer=iss or None)
                    ) from exc
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
                if alg != "none":
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
                    key_text=key_text if alg != "none" else None,
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
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            message = str(exc)
            status = HTTPStatus.BAD_REQUEST
            if message == "request body too large":
                status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            self._send_json({"error": message}, status=status)
        except jwt_exceptions.PyJWTError as exc:
            self._send_json({"error": format_jwt_error(exc)}, status=HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self.log_error("Unhandled error: %r", exc)
            self._send_json(
                {"error": "internal server error"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), JWTWorkbenchHandler)
    print(f"JWT Workbench web UI running on http://{host}:{port}")
    server.serve_forever()
