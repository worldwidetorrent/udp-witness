# witness 🧾

Not a fetch service — a **witness** service.

Give it a URL. It fetches the page and hands you a signed verdict: *"this page looked like X at time T."* Timestamped, SHA-256 hashed, Ed25519-signed. Anyone can verify offline with the public key.

## Use it

```bash
curl -X POST http://YOUR-HOST/witness \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}'
```

Response:

```json
{
  "id": "…",
  "url": "https://example.com",
  "fetched_at": "2026-09-18T…Z",
  "http_status": 200,
  "bytes": 1256,
  "sha256": "…",
  "key_id": "…",
  "signature": "…"
}
```

## Verify a verdict

1. `GET /.well-known/witness-key` → Ed25519 public key (JWK).
2. The signature covers the canonical JSON `{"url","fetched_at","sha256"}` (keys in that order, no whitespace).
3. Verify the Ed25519 signature. If it checks out, the page hashed to `sha256` at `fetched_at`. No trust in the server required beyond the key.

## Endpoints

- `POST /witness` — `{ "url": "https://…" }` → verdict
- `GET /verdict/:id` — stored verdict
- `GET /recent` — latest verdicts
- `GET /.well-known/witness-key` — public key
- `GET /health` — liveness

## Notes

- Private/local targets are blocked (SSRF guard on resolved IPs).
- 2 MB page cap, 15 s fetch timeout, 30 req/min per IP.
- Free while demand is being proven. Built by UDP.
