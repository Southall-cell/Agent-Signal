# V1 Release Readiness

## Scope reviewed

This review covers the one-command local setup, API health, browser dashboard, agent registration and directory, authenticated identity challenge, signed evidence, score/report generation, report signing and verification, credential rotation, persistence, hostile requests, and automated tests.

## What signatures and scores establish

- Identity verification establishes control of a locally configured Ed25519 key for a short-lived one-use challenge. It does not prove the real-world identity of the key holder.
- Permissions verification checks that the configured agent key signed the submitted action list. It does not establish that another system grants or enforces those permissions.
- Audit verification checks an agent signature over a submitted SHA-256 digest and timestamp. The API does not receive the underlying logs, verify completeness, or establish that the digest describes real events.
- The service’s Ed25519 signature detects changes to its report envelope and identifies the local signing key. A public key obtained from the same API is not an independent trust anchor; pin it through a trusted channel for independent verification.
- Incident counts are requester-supplied and not independently checked. Formula scores are not trust certifications or risk decisions.

## Assumptions and limits

- The app targets one local developer on a trusted machine and binds to loopback. The bootstrap token controls agent listing and registration. The local Agent Signal report-signing private key, agent private keys, SQLite database, and backups must be protected.
- Agent API keys are stored only as hashes. Agent IDs and the latest report are stored in SQLite. Rate limits, identity challenges, and short-lived identity proof state are process-local; multiple workers and internet-facing operation are not supported.
- The agent public-key registry is loaded at startup. Changing it requires restart. There is no external evidence source, independent permissions/audit verification, or mechanism to recover lost agent API keys.
- Replacing the local service report-signing key makes older report signatures unverifiable unless its old public key is retained separately. Verification is against the current local signing key.
- The browser requires Web Crypto Ed25519 support. The headless Chromium journey runs in CI; managed local sandboxes may prevent Chromium from launching.

## Verdict

**Ready for a local developer demo and testing with stated limits. Not ready for production or real-world trust decisions.** The browser workflow calls the real API and security checks, and reports are signed and persisted locally. The main assurance limit remains that the submitted permission, audit, and incident values are not independently sourced.

## Single most important next step

Connect permissions, audit data, and incident counts to independently controlled sources before using scores for assurance decisions.
