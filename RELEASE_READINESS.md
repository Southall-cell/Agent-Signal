# V1 Release Readiness

## Scope reviewed

This review covers a clean local setup from the documented quick start, service health and shutdown, the browser dashboard, the versioned registration/authentication/identity/evidence/scoring/report/key-rotation journey, hostile request handling, persistence, and automated tests. The dashboard uses the existing API and scoring engine; no weights or external validators were added.

## What the API establishes

- Identity verification establishes control of the configured Ed25519 private key for a one-use challenge during its short validity window. It does not establish the real-world identity of the key holder.
- Permissions verification establishes that the configured key signed the submitted list of allowed actions. It does not establish that another system grants or enforces those permissions.
- Audit verification establishes that the configured key signed a supplied SHA-256 digest and timestamp. The API does not receive the underlying logs, verify a chain or completeness, or establish that the digest describes real events.
- Incident counts are requester-supplied and are not independently checked. Scores are formula outputs, not trust certifications or risk decisions.
- The browser dashboard holds the current report in the tab because V1 has no assessment history endpoint. API keys remain in page memory unless downloaded by the user; the private key is read locally to sign evidence.

## Assumptions and limits

- The quick start targets one local developer on a trusted machine and binds to loopback. Registration needs the local bootstrap token; private keys, token files, the SQLite database, and backups must remain protected.
- SQLite persists registered agents and hashed API keys. Rate limits, challenges, and temporary identity proof state are process-local; this is not suitable for multiple workers or an internet-facing deployment.
- Public keys are loaded from a local file at startup. Changing that file requires a restart. There is no administrator identity, recovery flow, external evidence source, or independent audit/permission validation.
- The browser flow requires a modern browser with Web Crypto Ed25519 support. The headless Chromium lifecycle test runs in CI; sandboxed local runners may be unable to launch the Chromium child process.
- Dependencies are pinned for reproducibility. A clean first install requires access to a Python package index or a pre-populated package cache.

## Verdict

**Ready for a local developer handoff with stated limits. Not ready for production or for making real-world trust decisions.** The documented run path and tested API lifecycle are usable; the main assurance limitation is that permissions, audit events, and incident counts are not independently sourced.

## Single most important next step

Before using scores for an assurance decision, connect permissions, audit data, and incident counts to independently controlled sources and verify them server-side.
