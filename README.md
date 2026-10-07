# Agent Signal — Local Agent Trust API

A small V1 FastAPI app and browser dashboard for locally scoring submitted agent evidence. It persists agent credentials in SQLite and verifies Ed25519 identity, permissions manifests, and audit digests. It has no hosted dependencies or external runtime services.

## Quick start: install, configure, run, check, stop

From a clean checkout, run this in the project directory:

```sh
./run-local.sh
```

This one command creates `.venv/`, installs the pinned Python requirements, prepares a local registration token and development Ed25519 key pair under `.dev/`, then starts the API on `http://127.0.0.1:8000`. No manual environment configuration is needed for the local demo. Keep this terminal open while the server runs.

Open the dashboard at **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)** (or `/dashboard`). This is served by the same local API process; no separate frontend server or browser build step is needed.

### Run a safe demo assessment

1. In the dashboard, leave the agent ID as `demo-agent` and select **Register new**. If this agent was already registered, select **Use API key** and paste its saved key instead.
2. In a second terminal, read the local bootstrap token with `cat .dev/registration.env`. Paste only the value after `REGISTRATION_TOKEN=` into the password field. This file is generated locally with owner-only permissions.
3. Choose `.dev/demo-agent.pem` in the private-key file picker. The browser reads this key locally to sign the challenge and evidence; the file is not uploaded.
4. Keep the sample actions, audit note, and incident count, then click **Run assessment**. The page registers/authenticates the agent, verifies an identity challenge, signs the declared actions and audit digest, and requests the score and report from the existing V1 API.
5. Review the score and evidence explanation. Click **Save API key for later** if you want to authenticate in another tab or after closing this one. The browser holds the key in memory only until then; the downloaded key file is a secret and must be stored securely.

The report and “recent assessment” are held in the current page only because the API has no assessment-history endpoint. The dashboard makes no external requests. Its prominent evidence note distinguishes key-backed signature checks from requester-supplied data and states that permissions and history are not externally validated. The **Rotate API key** control revokes the current key immediately; save the replacement key if you rotate it.

The dashboard requires a modern browser with Web Crypto Ed25519 support. Open it through the local `127.0.0.1` URL so browser cryptography is enabled.

In a second terminal, check readiness:

```sh
curl -fsS http://127.0.0.1:8000/v1/health
```

Health returns `{"status":"ok","api_version":"v1"}`. The command-line example is an alternative complete signed-evidence flow:

```sh
./.venv/bin/python examples/e2e.py
```

It registers `demo-agent`, verifies a challenge, signs and submits evidence, fetches a report, and saves its API key in `.dev/demo-agent.api-key` with owner-only permissions. The CLI and dashboard share this demo agent: if you run the CLI first, choose **Use API key** in the dashboard and paste that saved key. If you register with the dashboard first, the CLI cannot register the same agent again unless you copy the downloaded key to `.dev/demo-agent.api-key`. Stop the server with `Ctrl-C` in the first terminal.

To change the local port, set `PORT`, for example `PORT=8080 ./run-local.sh`.

## Docker Compose

Create a virtual environment and the local development credentials, then build and start the API:

```sh
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
PYTHON_BIN=./.venv/bin/python ./prepare-dev.sh
docker compose up --build
```

The service is published only on `127.0.0.1:8000`. SQLite data and development credentials stay in `.dev/` on the host and are shared with local runs. The container receives the public key file, SQLite database, and local registration token, not the agent private key. Run the example from the host in another terminal:

```sh
./.venv/bin/python examples/e2e.py
```

Stop the service with `Ctrl-C`. `docker compose down` stops it and keeps local data. To reset the development agent and its saved credential after stopping the service, remove `.dev/agents.sqlite3` and `.dev/demo-agent.api-key`; keep `.dev/agents.sqlite3.legacy-imported` if present so an old JSON backup cannot restore stale keys. `./prepare-dev.sh` recreates the empty database file on the next start.

## Tests

```sh
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt -r requirements-test.txt
./.venv/bin/python -m playwright install chromium
./.venv/bin/python -m unittest discover -v
```

On a fresh Ubuntu or Debian machine, install Chromium and its operating-system dependencies with:

```sh
./.venv/bin/python -m playwright install --with-deps chromium
```

The suite includes the Python API/web tests and a real headless Chromium journey. The browser test creates an isolated API and temporary Ed25519 key, checks an authentication error, registers and authenticates through the dashboard, signs the challenge and evidence in the browser, checks the score and explanation, rotates the key, and verifies the old key is rejected. It also checks that private key material is not sent to the API or persisted in browser storage. Playwright and Chromium are test-only dependencies and are not installed by `run-local.sh`. GitHub Actions installs Python, Playwright, Chromium, and Linux browser dependencies, runs the complete suite, then starts the API and waits for its health endpoint before the documented CLI flow. The workflow does not deploy the API. The browser test needs permission to launch a local Chromium process; managed execution sandboxes may report that specific test as skipped, while regular developer machines and CI should run it.

See [API.md](API.md) for routes, request and response examples, authentication, errors, evidence formats, and local security limits. See [RELEASE_READINESS.md](RELEASE_READINESS.md) for scope and assurance limitations.
