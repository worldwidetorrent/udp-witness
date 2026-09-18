'use strict';
/*
 * UDP witness service — signed webpage verdicts.
 *
 *   POST /witness   { "url": "https://example.com" }  -> signed verdict
 *   GET  /verdict/:id                              -> stored verdict
 *   GET  /recent                                   -> latest verdicts
 *   GET  /.well-known/witness-key                  -> Ed25519 public key (JWK)
 *   GET  /health                                   -> { ok: true }
 *
 * A verdict is: "this page looked like X at time T", signed with the
 * instance's Ed25519 key. Anyone can verify offline with the public key.
 *
 * Zero dependencies. Verdicts: ./data/verdicts/<id>.json (or $DATA_DIR).
 */
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '80', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const VERDICT_DIR = path.join(DATA_DIR, 'verdicts');
const KEY_PATH = process.env.KEY_PATH || path.join(__dirname, 'witness-key.json');
const MAX_BYTES = 2 * 1000 * 1000;
const FETCH_TIMEOUT_MS = 15000;
const MAX_REDIRECTS = 3;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 30;

fs.mkdirSync(VERDICT_DIR, { recursive: true });

/* ---------------- keypair ---------------- */
function loadOrCreateKey() {
  try {
    const saved = JSON.parse(fs.readFileSync(KEY_PATH, 'utf8'));
    const priv = crypto.createPrivateKey({ key: saved.privateJwk, format: 'jwk' });
    return { priv, pubJwk: crypto.createPublicKey(priv).export({ format: 'jwk' }) };
  } catch {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(KEY_PATH, JSON.stringify({ privateJwk: privateKey.export({ format: 'jwk' }) }, null, 2), { mode: 0o600 });
    return { priv: privateKey, pubJwk: publicKey.export({ format: 'jwk' }) };
  }
}
const { priv: PRIV, pubJwk: PUB_JWK } = loadOrCreateKey();
PUB_JWK.kid = crypto.createHash('sha256').update(PUB_JWK.x, 'base64url').digest('hex').slice(0, 12);

/* ---------------- SSRF guard ---------------- */
function ipIsBlocked(ip) {
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    return l === '::1' || l === '::' || l.startsWith('fe80:') ||
      l.startsWith('fc') || l.startsWith('fd') || l.startsWith('ff');
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  return a === 10 || a === 127 || a === 0 || a >= 224 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127);
}

async function assertPublicUrl(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { throw httpError(400, 'bad url'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw httpError(400, 'only http(s) urls');
  if (!u.hostname) throw httpError(400, 'bad url');
  const addrs = await dns.lookup(u.hostname, { all: true }).catch(() => null);
  if (!addrs || !addrs.length) throw httpError(502, 'dns lookup failed');
  if (addrs.some(a => ipIsBlocked(a.address))) throw httpError(403, 'private/local targets are blocked');
  return u;
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

/* ---------------- fetch ---------------- */
function fetchOnce(u) {
  return new Promise((resolve, reject) => {
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.get(u, {
      timeout: FETCH_TIMEOUT_MS,
      headers: { 'User-Agent': 'udp-witness/1.0 (+signed webpage verdicts)' },
    }, resolve);
    req.on('timeout', () => req.destroy(httpError(502, 'fetch timeout')));
    req.on('error', reject);
  });
}

async function fetchPage(urlStr) {
  let u = await assertPublicUrl(urlStr);
  let res = null;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    res = await fetchOnce(u);
    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
      res.resume(); // drain
      u = await assertPublicUrl(new URL(res.headers.location, u).toString());
      res = null;
      continue;
    }
    break;
  }
  if (!res) throw httpError(502, 'too many redirects');
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    res.on('data', c => {
      size += c.length;
      if (size > MAX_BYTES) { res.destroy(); reject(httpError(413, 'page too large')); return; }
      chunks.push(c);
    });
    res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    res.on('error', reject);
  });
}

/* ---------------- verdicts ---------------- */
function signVerdictFields(v) {
  const payload = JSON.stringify({ url: v.url, fetched_at: v.fetched_at, sha256: v.sha256 });
  return crypto.sign(null, Buffer.from(payload), PRIV).toString('base64url');
}

function makeVerdict(url, fetched) {
  const v = {
    id: crypto.randomUUID(),
    url,
    fetched_at: new Date().toISOString(),
    http_status: fetched.status,
    bytes: fetched.body.length,
    sha256: crypto.createHash('sha256').update(fetched.body).digest('hex'),
    key_id: PUB_JWK.kid,
  };
  v.signature = signVerdictFields(v);
  fs.writeFileSync(path.join(VERDICT_DIR, v.id + '.json'), JSON.stringify(v, null, 2));
  return v;
}

function recentVerdicts(limit = 10) {
  const files = fs.readdirSync(VERDICT_DIR).filter(f => f.endsWith('.json'))
    .map(f => ({ f, t: fs.statSync(path.join(VERDICT_DIR, f)).mtimeMs }))
    .sort((a, b) => b.t - a.t).slice(0, limit);
  return files.map(({ f }) => {
    const v = JSON.parse(fs.readFileSync(path.join(VERDICT_DIR, f), 'utf8'));
    return { id: v.id, url: v.url, fetched_at: v.fetched_at, sha256: v.sha256 };
  });
}

/* ---------------- rate limit ---------------- */
const buckets = new Map();
function rateLimited(ip) {
  const now = Date.now();
  let b = buckets.get(ip);
  if (!b || now > b.reset) { b = { count: 0, reset: now + RATE_WINDOW_MS }; buckets.set(ip, b); }
  b.count++;
  return b.count > RATE_MAX;
}

/* ---------------- http ---------------- */
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function readBody(req, max = 10 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > max) { req.destroy(); reject(httpError(413, 'body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const LANDING = `<!doctype html><html><head><meta charset="utf-8"><title>witness — signed webpage verdicts</title>
<style>body{font-family:system-ui;max-width:640px;margin:3rem auto;padding:0 1rem;line-height:1.6}code{background:#f0f0f0;padding:2px 6px;border-radius:4px}pre{background:#f6f6f6;padding:1rem;overflow:auto;border-radius:8px}</style>
</head><body>
<h1>witness &#129532;</h1>
<p>Not a fetch service — a <b>witness</b> service. Give it a URL, it fetches the page and hands you a signed verdict: <i>"this page looked like X at time T."</i> Timestamped, hashed, signed with Ed25519. Verify offline.</p>
<h3>Use it</h3>
<pre><code>curl -X POST /witness -H 'Content-Type: application/json' \\
  -d '{"url":"https://example.com"}'</code></pre>
<h3>Verify a verdict</h3>
<p>Fetch the public key at <code>/.well-known/witness-key</code>, then check the Ed25519 signature over the canonical JSON <code>{"url","fetched_at","sha256"}</code>.</p>
<p><a href="/recent">recent verdicts</a> &middot; <a href="/health">health</a></p>
<p><small>Free while demand is being proven. Built by UDP.</small></p>
</body></html>`;

const server = http.createServer(async (req, res) => {
  try {
    const ip = req.socket.remoteAddress || 'unknown';
    if (rateLimited(ip)) return send(res, 429, { error: 'slow down' });
    const u = new URL(req.url, 'http://x');

    if (req.method === 'GET' && u.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': Buffer.byteLength(LANDING) });
      return res.end(LANDING);
    }
    if (req.method === 'GET' && u.pathname === '/health') return send(res, 200, { ok: true, time: new Date().toISOString() });
    if (req.method === 'GET' && u.pathname === '/.well-known/witness-key') return send(res, 200, PUB_JWK);
    if (req.method === 'GET' && u.pathname === '/recent') return send(res, 200, recentVerdicts());
    if (req.method === 'GET' && u.pathname.startsWith('/verdict/')) {
      const id = u.pathname.slice(9).replace(/[^a-f0-9-]/gi, '');
      const p = path.join(VERDICT_DIR, id + '.json');
      if (!fs.existsSync(p)) return send(res, 404, { error: 'no such verdict' });
      return send(res, 200, JSON.parse(fs.readFileSync(p, 'utf8')));
    }
    if (req.method === 'POST' && u.pathname === '/witness') {
      let body;
      try { body = JSON.parse(await readBody(req)); } catch { return send(res, 400, { error: 'invalid json' }); }
      if (!body || typeof body.url !== 'string' || !body.url.length) return send(res, 400, { error: 'missing url' });
      const fetched = await fetchPage(body.url);
      return send(res, 200, makeVerdict(body.url, fetched));
    }
    return send(res, 404, { error: 'not found' });
  } catch (e) {
    return send(res, e.status || 500, { error: e.message || 'boom' });
  }
});

server.listen(PORT, () => console.log(`witness up on :${PORT}`));
