# Local Trust Scoring API — V1

## Run locally

The fastest local start is `./run-local.sh`. It creates `.venv/` and local development keys on first run, then binds the API to loopback. Open the browser dashboard at `http://127.0.0.1:8000/`; it uses these same versioned API routes. Run `./.venv/bin/python examples/e2e.py` in another terminal for a command-line signed-evidence flow. See [README.md](README.md) for dashboard steps, Docker Compose, and reset instructions.

The API runs at `http://127.0.0.1:8000`; FastAPI's interactive docs are at `/docs` and its OpenAPI schema is at `/openapi.json`.

Manual server start, after installing `requirements.txt`, configuring the key registry, and setting a secret `REGISTRATION_TOKEN`:

```sh
uvicorn app:app --host 127.0.0.1 --port 8000
```

The preferred API paths are versioned under `/v1`. Unversioned routes remain as compatibility aliases. Agent credentials persist in local SQLite (`agents.sqlite3` by default); limiter and identity challenge state remain process-local.

## Health and status

- `GET /v1/health`
- `GET /v1/status` (alias)

Example response:

```json
{"status":"ok","api_version":"v1"}
```

## Register and authenticate agents

`POST /v1/agents/register` requires an `X-Registration-Token` bootstrap secret of at least 32 characters and returns a random API key once. The bootstrap token is rate-limited; only the API key's SHA-256 hash is stored in SQLite. Set `REGISTRATION_TOKEN` and `AGENTS_DB_FILE` in the server environment. Existing `agents.json` fingerprints are imported once; `AGENTS_FILE` selects the legacy import file. After import, the source is renamed to `agents.json.migrated` and a `.legacy-imported` marker is created next to the database, preventing stale hashes from being imported after a database reset. Registering an existing ID returns `409`.

```http
POST /v1/agents/register
X-Registration-Token: <local bootstrap token>
Content-Type: application/json

{"agent_id":"demo-agent"}
```

```json
{"agent_id":"demo-agent","api_key":"<save this key; it is returned once>"}
```

Rotate the bootstrap token by replacing `REGISTRATION_TOKEN` in the local environment file and restarting/recreating the API. The old token then stops authorizing registrations. The API-key rotation route is separate and rotates one registered agent's API key.

All score routes (`GET /v1/score`, `POST /v1/score`, `POST /v1/score/report`, and `POST /v1/score/report/signed`) require the agent's matching `X-API-Key` header. Identity challenge and verify routes also require that agent's API key. Missing, invalid, or another agent's key returns `401`.

## Rotate an API key

`POST /v1/agents/rotate-key` requires the current key in `X-API-Key`. It returns a replacement once; the previous key is invalid immediately.

```http
POST /v1/agents/rotate-key
X-API-Key: <current API key>
Content-Type: application/json

{"agent_id":"demo-agent"}
```

```json
{"agent_id":"demo-agent","api_key":"<save the replacement key>"}
```

The dashboard uses key rotation to revoke the previous credential. The agent registration remains active under the replacement key; V1 does not delete or disable an agent record.

## Agent directory and saved reports

The local dashboard lists agents with the `X-Registration-Token` because V1 has no separate administrator account. These routes return agent IDs and scores/reports only; they never return API keys or stored key hashes.

- `GET /v1/agents` returns registered IDs, active status, and the latest saved score/rating.
- `GET /v1/agents/{agent_id}` returns the latest report and, when available, its signed envelope.

The registration token must meet the same strength requirement as registration and shares its rate limit. Latest reports are stored in a `latest_reports` SQLite table. Calling the existing `/score/report` endpoint still returns the same report shape and saves it without a service signature.

## Signed report and verification

`POST /v1/score/report/signed` accepts the same authenticated evidence request as `/v1/score/report`. It returns a report envelope signed with the local service Ed25519 key and persists it with the latest agent report. The agent evidence is still checked exactly as described below; the service signature protects the report contents after calculation. The following is an abbreviated schema illustration; the report field contains the complete existing trust-report object.

```json
{
  "report_id": "<unique report ID>",
  "algorithm": "Ed25519",
  "signing_key_id": "<SHA-256-derived key ID>",
  "report": {"agent_id":"demo-agent","overall_score":95,"rating":"high_score"},
  "signature": "<Base64 service signature over the complete canonical envelope>"
}
```

The complete `report` object contains the existing trust report fields. `GET /v1/reports/signing-key` returns the service public key and key ID. `POST /v1/reports/verify` accepts the complete signed envelope and returns `valid: true` or `valid: false`; altered report fields fail verification. Verification uses the current local signing key. Replacing that key makes older signatures unverifiable unless the old public key was separately retained. For independent verification, distribute and pin the public key through a trusted channel; fetching it from the same API does not protect against a compromised API host.

The private service signing key is generated under `.dev/report-signing-key.pem` with owner-only permissions by `prepare-dev.sh`. It never leaves the API host. The browser verifier submits public report data to the local API and does not handle any signing private key.

## Score and reports

Weights remain unchanged: base 50, +15 for each verified identity, signed permissions manifest, and signed audit digest; −10 per submitted incident; clamp final score to 0–100. The numeric score bands are named `high_score` at 80+, `review` at 50–79, and `low_score` below 50. These labels describe only the formula result; they are not a trust certification.

V1 compatibility note: clients should accept the rating labels `high_score`, `review`, and `low_score`; the earlier `trusted` and `high_risk` labels were removed because they implied more assurance than this API provides. Scores and weights are unchanged.

Send the registration key in `X-API-Key`:

```http
POST /v1/score/report
X-API-Key: <agent API key>
Content-Type: application/json
```

```json
{
  "agent_id": "demo-agent",
  "permission_manifest": {
    "allowed_actions": ["read:profile", "write:notes"],
    "signature": "<base64 Ed25519 signature>"
  },
  "audit_log": {
    "digest": "<64-character SHA-256 hex digest>",
    "created_at": "<recent UTC timestamp>",
    "signature": "<base64 Ed25519 signature>"
  },
  "incident_count": 0
}
```

Create signatures locally with `sign_permissions_manifest.py` and `sign_audit_digest.py`. Audit proofs expire after five minutes; timestamps up to 30 seconds in the future are allowed for clock skew. Identity challenges expire after 60 seconds and successful identity proofs last five minutes.

### Verify identity

The authenticated agent requests a challenge. The server only issues one when that agent's public key is configured locally. Sign the returned `challenge` UTF-8 bytes with the agent's Ed25519 private key, then submit its Base64 signature. Challenges are single-use and expire after 60 seconds. Challenge issuance and verification consume the same per-agent rate-limit budget as score requests.

```http
POST /v1/identity/challenge
X-API-Key: <agent API key>
Content-Type: application/json

{"agent_id":"demo-agent"}
```

```json
{
  "agent_id": "demo-agent",
  "challenge_id": "<one-time challenge ID>",
  "challenge": "<random challenge text>",
  "expires_at": "2026-10-06T12:00:00Z"
}
```

```http
POST /v1/identity/verify
X-API-Key: <agent API key>
Content-Type: application/json

{"agent_id":"demo-agent","challenge_id":"<one-time challenge ID>","signature":"<Base64 Ed25519 signature over challenge UTF-8 bytes>"}
```

Successful response:

```json
{
  "agent_id": "demo-agent",
  "verified": true,
  "reason": "Ed25519 challenge signature verified.",
  "checked_at": "2026-10-06T12:00:01Z"
}
```

`POST /v1/score/report` returns `overall_score`, `rating`, `base_score`, a `factor_scores` array (including the incident adjustment), `evidence_results`, readable `reasons`, and UTC `checked_at`. `/v1/score` returns the compact form. `GET /v1/score?agent_id=demo-agent` returns a neutral score for that authenticated agent.

Example report factor:

```json
{
  "factor": "permission_declared",
  "points": 15,
  "max_points": 15,
  "status": "verified",
  "verification": "cryptographic",
  "reason": "Permissions manifest signature verified."
}
```

## Error responses

Errors use one JSON envelope across HTTP errors, validation failures, and oversized bodies. The `detail` field remains as a compatibility alias for the message.

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Request validation failed. See error.details for field-level guidance.",
    "details": [
      {"field": "body.incident_count", "message": "Field required", "code": "missing"}
    ]
  },
  "detail": "Request validation failed. See error.details for field-level guidance."
}
```

Common error codes include `unauthorized` (401), `not_found` (404), `conflict` (409), `expired` (410), `request_too_large` (413), `invalid_request` (422), `rate_limited` (429), and `temporarily_unavailable` (503). Rate-limit responses include `Retry-After`.

## What V1 verifies

- **Identity:** the configured Ed25519 public key verified a signature over a random, short-lived challenge. This proves control of that key for the challenge window; identity ownership outside the local key registry is not established.
- **Permissions:** the configured public key verified that the agent signed the listed `allowed_actions`. V1 does not check that the actions are actually granted or enforced by another system.
- **Audit log:** the configured public key verified a signature over the submitted SHA-256 digest and timestamp. V1 does not receive the log contents, verify a hash chain, check completeness, or establish that the digest describes real events. A valid proof can be reused during its five-minute window; a permissions manifest has no expiry.
- **Incidents:** `incident_count` is supplied by the score requester and is not independently verified. An agent can submit zero incidents.

Accordingly, the score reports key-backed evidence claims and a formula result; it does not establish real-world trustworthiness or risk. Use an independently controlled source for permissions, audit data, and incident counts before treating a score as an assurance decision.

## Configure a custom agent key

The local quick start creates only the `demo-agent` key pair. For another identity, generate an Ed25519 key pair and add its public key to the configured registry before starting the API:

```sh
./.venv/bin/python generate_agent_keypair.py \
  --agent-id another-agent \
  --private-key-out .dev/another-agent.pem \
  --registry .dev/agent_public_keys.json
```

Restart the API after editing the registry; keys are loaded at process startup. Keep the private key outside the API container and protect it as a secret.

## Rate limiting

Authenticated score, identity, and key-rotation requests share a **60 requests per agent per 60-second fixed window** by default. Registration requests share a separate budget per bootstrap token. The agent counter follows the stable agent ID across key rotation, so rotating credentials cannot reset the budget. `API_RATE_LIMIT_MAX_REQUESTS` and `API_RATE_LIMIT_WINDOW_SECONDS` configure this for the local process. Exceeded limits return `429` with a `Retry-After` header. Counters are in memory and reset when the process restarts. Request bodies are capped at 64 KiB and incident counts at 1,000,000.

## Local security model and limits

- API keys are generated from 256 bits of randomness. The database stores only their SHA-256 fingerprints; key comparisons use constant-time comparison. Rotation uses a SQLite compare-and-swap update, so at most one concurrent request using a given old key can succeed. The old key is invalid immediately.
- SQLite is the persistence boundary for agent registration and current keys. The database file is created with mode `0600`; protect its parent directory and backups as local credential material.
- Identity challenges are random, one-use, expire after 60 seconds, require the agent API key, and are consumed atomically. Pending and replay-tracking state is bounded. Permissions and audit evidence remain Ed25519-verified against locally configured public keys.
- Rate limits, challenges, and verified identity proof windows are process-local. Restarting the service resets those controls, so this is intended for a single local API process, not a multi-worker or internet-facing deployment.
- Registration requires a local bootstrap token, but there is no administrator identity or account recovery path. The token can be rotated by changing configuration and restarting. Bind to loopback and keep the local machine, token file, public-key registry, and SQLite file trusted.
- Request model bounds and the body cap reject malformed or oversized inputs. The API does not defend against a hostile local user who can edit the database or public-key file, read process memory, or replace the running code.
