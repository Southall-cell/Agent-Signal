"""SQLite-backed local agent registry; only one-way API-key hashes are persisted."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from typing import Optional


class AgentAlreadyRegistered(Exception):
    pass


class InvalidAgentKey(Exception):
    pass


class SQLiteAgentStore:
    """Persistence boundary for agent IDs and their current API-key fingerprints."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(descriptor)
        os.chmod(self.path, 0o600)
        self._lock = threading.RLock()
        with closing(self._connect()) as connection:
            with connection:
                connection.execute("""CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    key_hash TEXT NOT NULL CHECK(length(key_hash) = 64)
                )""")
                connection.execute("""CREATE TABLE IF NOT EXISTS latest_reports (
                    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
                    report_json TEXT NOT NULL,
                    signed_report_json TEXT,
                    updated_at TEXT NOT NULL
                )""")

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level="IMMEDIATE")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def get_hash(self, agent_id: str):
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute("SELECT key_hash FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
            return row[0] if row else None

    def create(self, agent_id: str, key_hash: str) -> None:
        with self._lock, closing(self._connect()) as connection:
            try:
                with connection:
                    connection.execute("INSERT INTO agents(agent_id, key_hash) VALUES (?, ?)", (agent_id, key_hash))
            except sqlite3.IntegrityError as exc:
                raise AgentAlreadyRegistered(agent_id) from exc

    def replace_hash(self, agent_id: str, current_hash: str, new_hash: str) -> bool:
        """Compare-and-swap ensures concurrent rotations cannot both succeed."""
        with self._lock, closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    "UPDATE agents SET key_hash = ? WHERE agent_id = ? AND key_hash = ?",
                    (new_hash, agent_id, current_hash),
                )
                return cursor.rowcount == 1

    def contains(self, agent_id: str) -> bool:
        return self.get_hash(agent_id) is not None

    def list_agents(self) -> list[dict]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute("""SELECT agents.agent_id, latest_reports.report_json,
                    latest_reports.signed_report_json, latest_reports.updated_at
                FROM agents LEFT JOIN latest_reports ON agents.agent_id = latest_reports.agent_id
                ORDER BY latest_reports.updated_at IS NULL, latest_reports.updated_at DESC,
                    agents.agent_id COLLATE NOCASE""").fetchall()
        return [
            {
                "agent_id": row[0],
                "report": json.loads(row[1]) if row[1] else None,
                "signed_report": json.loads(row[2]) if row[2] else None,
                "updated_at": row[3],
            }
            for row in rows
        ]

    def get_agent(self, agent_id: str) -> Optional[dict]:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute("""SELECT agents.agent_id, latest_reports.report_json,
                    latest_reports.signed_report_json, latest_reports.updated_at
                FROM agents LEFT JOIN latest_reports ON agents.agent_id = latest_reports.agent_id
                WHERE agents.agent_id = ?""", (agent_id,)).fetchone()
        if row is None:
            return None
        return {
            "agent_id": row[0],
            "report": json.loads(row[1]) if row[1] else None,
            "signed_report": json.loads(row[2]) if row[2] else None,
            "updated_at": row[3],
        }

    def save_report(self, agent_id: str, report: dict, signed_report: Optional[dict] = None) -> None:
        report_json = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        signed_json = (
            json.dumps(signed_report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if signed_report is not None else None
        )
        updated_at = report["checked_at"]
        with self._lock, closing(self._connect()) as connection:
            with connection:
                connection.execute("""INSERT INTO latest_reports(agent_id, report_json, signed_report_json, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(agent_id) DO UPDATE SET
                        report_json = excluded.report_json,
                        signed_report_json = excluded.signed_report_json,
                        updated_at = excluded.updated_at""",
                    (agent_id, report_json, signed_json, updated_at))

    def health_check(self) -> bool:
        try:
            with self._lock, closing(self._connect()) as connection:
                connection.execute("SELECT key_hash FROM agents LIMIT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def import_hashes(self, hashes: dict[str, str]) -> None:
        with self._lock, closing(self._connect()) as connection:
            with connection:
                connection.executemany(
                    "INSERT OR IGNORE INTO agents(agent_id, key_hash) VALUES (?, ?)",
                    hashes.items(),
                )


class AgentRegistry:
    """Credential operations over an injected store abstraction."""

    def __init__(self, path: Path, store=None):
        self.store = store or SQLiteAgentStore(path)
        self._lock = threading.RLock()

    @staticmethod
    def _hash(api_key: str) -> str:
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    def register(self, agent_id: str) -> str:
        api_key = secrets.token_urlsafe(32)
        self.store.create(agent_id, self._hash(api_key))
        return api_key

    def key_fingerprint(self, agent_id: str, api_key: str):
        stored_hash = self.store.get_hash(agent_id)
        supplied_hash = self._hash(api_key) if isinstance(api_key, str) else "0" * 64
        expected_hash = stored_hash if stored_hash is not None else "0" * 64
        if hmac.compare_digest(expected_hash, supplied_hash) and stored_hash is not None:
            return stored_hash
        return None

    def verify(self, agent_id: str, api_key: str) -> bool:
        return self.key_fingerprint(agent_id, api_key) is not None

    def rotate(self, agent_id: str, current_key: str) -> str:
        current_hash = self._hash(current_key) if isinstance(current_key, str) else "0" * 64
        new_key = secrets.token_urlsafe(32)
        if not self.store.replace_hash(agent_id, current_hash, self._hash(new_key)):
            raise InvalidAgentKey(agent_id)
        return new_key

    def contains(self, agent_id: str) -> bool:
        return self.store.contains(agent_id)

    def list_agents(self) -> list[dict]:
        return self.store.list_agents()

    def get_agent(self, agent_id: str):
        return self.store.get_agent(agent_id)

    def save_report(self, agent_id: str, report: dict, signed_report: Optional[dict] = None) -> None:
        self.store.save_report(agent_id, report, signed_report)

    def health_check(self) -> bool:
        return self.store.health_check()


_DEFAULT_JSON = Path(os.environ.get("AGENTS_FILE", Path(__file__).with_name("agents.json")))
DEFAULT_DB = Path(os.environ.get("AGENTS_DB_FILE", _DEFAULT_JSON.with_suffix(".sqlite3") if "AGENTS_FILE" in os.environ else Path(__file__).with_name("agents.sqlite3")))


def migrate_legacy_json(source: Path, destination: Path) -> int:
    """Import legacy hashes once and preserve a marker outside the replaceable DB."""
    if not source.exists() or source.resolve() == destination.resolve():
        return 0
    marker = destination.with_name(destination.name + ".legacy-imported")
    if marker.exists():
        return 0
    try:
        values = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read legacy agent registry {source}.") from exc
    valid = isinstance(values, dict) and all(
        isinstance(agent_id, str) and 1 <= len(agent_id) <= 128
        and isinstance(key_hash, str) and len(key_hash) == 64
        and all(char in "0123456789abcdef" for char in key_hash)
        for agent_id, key_hash in values.items()
    )
    if not valid:
        raise RuntimeError("Legacy agent registry must contain agent IDs and lowercase SHA-256 key hashes.")
    SQLiteAgentStore(destination).import_hashes(values)
    archive = source.with_name(source.name + ".migrated")
    while archive.exists():
        archive = source.with_name(source.name + ".migrated-" + secrets.token_hex(4))
    source.replace(archive)
    marker.parent.mkdir(parents=True, exist_ok=True)
    temporary = marker.with_name(marker.name + ".tmp-" + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            file.write(str(source.resolve()) + "\n")
        try:
            os.link(temporary, marker)
        except FileExistsError:
            pass
    finally:
        if temporary.exists():
            temporary.unlink()
    return len(values)


if _DEFAULT_JSON.exists():
    migrate_legacy_json(_DEFAULT_JSON, DEFAULT_DB)
REGISTRY = AgentRegistry(DEFAULT_DB)
