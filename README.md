# Agent Signal

Agent Signal is a local workspace for registering AI agents, scoring submitted evidence, and inspecting signed reports. The browser app uses the existing FastAPI service and SQLite registry; it does not contact hosted services.

## Start the app

From a fresh checkout, open a terminal in the project directory and run:

```sh
./run-local.sh
```

The launcher creates a Python virtual environment, installs the pinned API dependencies, and prepares local development credentials on first run. It then starts the API and web app on loopback.

Open **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)** in your browser. Keep the terminal running; press `Ctrl-C` there to stop the app.

## First browser walkthrough

1. Find the local registration token in a second terminal with `cat .dev/registration.env`. Copy only the value after `REGISTRATION_TOKEN=` and paste it into **Connect this workspace**. The token stays in the browser tab’s memory and is used to list local agents and register new ones.
2. Choose **New assessment**. Leave the agent ID as `demo-agent` for the included local key, or use another ID whose public key has been added to `.dev/agent_public_keys.json` before starting the API.
3. Choose **Register new** for a new agent or **Use API key** for an existing one. Select that agent’s Ed25519 private key file. The browser reads it to sign the challenge and evidence; it is never uploaded or saved by the app.
4. Keep or edit the example action list, audit note, and incident count, then run the assessment. Agent Signal sends the evidence to the API, displays the formula score and evidence reasons, and stores the latest report locally.
5. Open the agent from **Registered agents** to inspect the score, rating, factors, status, report ID, and complete signed report JSON. **Verify signature** checks the report envelope with the local service’s Ed25519 public key. Edit the JSON in **Verify report** to see altered report content fail verification.
6. **Rotate and revoke old key** uses the existing API-key rotation route. The page confirms that the old credential now receives HTTP 401 and the replacement works. The agent remains registered. The replacement API key stays in this tab’s memory; choose **Save current API key** if you need it after closing the tab.

Agent IDs, latest reports, and signed report envelopes are stored in the local SQLite database. Agent API keys are stored there only as hashes. The registration token and development private keys live under `.dev/`, which is ignored by Git and created with owner-only file permissions.

## What signatures establish

- An agent signature verifies that the configured agent key signed the submitted challenge, permissions declaration, or audit digest. It does not independently validate real-world identity, actual permissions, audit history, or the requester-supplied incident count.
- The report envelope has a separate Ed25519 signature from the local Agent Signal service key. This detects changes to a signed report and identifies the signing key. The browser obtains the public key from the same local service; for independent verification, obtain and pin that public key through a trusted channel.
- The score is the existing formula output, not a trust certification or independent risk decision.

The service report-signing private key is generated locally as `.dev/report-signing-key.pem`, remains on the API host, and is never returned by an endpoint. Reports created before the signed-report route was used remain viewable but have no service signature; run a new assessment to create a signed envelope.

## Other local commands

Check the health endpoint:

```sh
curl -fsS http://127.0.0.1:8000/v1/health
```

FastAPI’s interactive API docs are at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs). For a command-line assessment instead of the browser, use `./.venv/bin/python examples/e2e.py` while the API is running.

To use a different local port, run `PORT=8080 ./run-local.sh` and open `http://127.0.0.1:8080/`.

## Docker Compose

After Docker is installed, prepare the same local files and start the service:

```sh
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
PYTHON_BIN=./.venv/bin/python ./prepare-dev.sh
docker compose up --build
```

Open `http://127.0.0.1:8000/`. Compose binds only to loopback and mounts the SQLite database, public agent keys, registration token, and service report-signing key into the local container. It does not mount the agent’s private key. Stop with `Ctrl-C` or run `docker compose down`; local data stays on disk.

## Run tests

```sh
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt -r requirements-test.txt
./.venv/bin/python -m playwright install chromium
./.venv/bin/python -m unittest discover -v
```

On Ubuntu or Debian, install Chromium and its system dependencies with `./.venv/bin/python -m playwright install --with-deps chromium`. The browser test exercises workspace authentication, registration, browser-side challenge and evidence signing, score/report display, valid and tampered report verification, API-key rotation, and rejection of the revoked key. GitHub Actions runs the full suite and repeats the browser journey three times. Local managed sandboxes that prevent Chromium from launching may skip that test; CI is the browser-capable check.

See [API.md](API.md) for routes, request/response shapes, authentication, and local security boundaries. See [RELEASE_READINESS.md](RELEASE_READINESS.md) for scope and limitations.
