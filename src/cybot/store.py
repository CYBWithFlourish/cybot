from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

SECRET_NAMES = {
    "ollama",
    "gemini",
    "grok",
    "anthropic",
    "openai",
    "shodan",
    "virustotal",
    "nvd",
    "telegram",
    "openrouter",
    "opencode",
    "pushover_user",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
  name TEXT PRIMARY KEY,
  ciphertext BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  target TEXT NOT NULL,
  program TEXT NOT NULL,
  intensity TEXT NOT NULL,
  status TEXT NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  scope_json TEXT NOT NULL,
  source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  host TEXT NOT NULL,
  tool TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  evidence TEXT NOT NULL,
  plain TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  run_id TEXT,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  decision TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
  run_id TEXT PRIMARY KEY,
  markdown TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS terminal (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  command TEXT NOT NULL,
  status TEXT NOT NULL,
  output TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_fernet(data_dir: Path, master_key: str | None) -> Fernet:
    data_dir.mkdir(parents=True, exist_ok=True)
    if master_key:
        try:
            return Fernet(master_key.encode() if isinstance(master_key, str) else master_key)
        except (ValueError, TypeError) as exc:
            raise SystemExit("CYBOT_MASTER_KEY is not a valid Fernet key.") from exc
    path = data_dir / "master.key"
    if path.exists():
        key = path.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        fd = path.open("wb")
        try:
            path.chmod(0o600)
            fd.write(key)
        finally:
            fd.close()
        path.chmod(0o600)
    return Fernet(key)


class Store:
    def __init__(self, path: Path, fernet: Fernet):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.fernet = fernet
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(_SCHEMA)
            columns = {row[1] for row in self.conn.execute("PRAGMA table_info(runs)")}
            if "notion" not in columns:
                self.conn.execute("ALTER TABLE runs ADD COLUMN notion TEXT NOT NULL DEFAULT 'ask'")
            finding_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(findings)")}
            if "jev" not in finding_columns:
                self.conn.execute("ALTER TABLE findings ADD COLUMN jev TEXT NOT NULL DEFAULT ''")
            if "playbook" not in finding_columns:
                self.conn.execute("ALTER TABLE findings ADD COLUMN playbook TEXT NOT NULL DEFAULT ''")
            run_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(runs)")}
            if "playbook" not in run_columns:
                self.conn.execute("ALTER TABLE runs ADD COLUMN playbook TEXT NOT NULL DEFAULT ''")
            run_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(runs)")}
            if "mode" not in run_columns:
                self.conn.execute("ALTER TABLE runs ADD COLUMN mode TEXT NOT NULL DEFAULT 'passive'")
            if "attestation" not in run_columns:
                self.conn.execute("ALTER TABLE runs ADD COLUMN attestation TEXT NOT NULL DEFAULT ''")
            finding_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(findings)")}
            if "confidence" not in finding_columns:
                self.conn.execute("ALTER TABLE findings ADD COLUMN confidence TEXT NOT NULL DEFAULT ''")
            if "repro" not in finding_columns:
                self.conn.execute("ALTER TABLE findings ADD COLUMN repro TEXT NOT NULL DEFAULT ''")
            if "needs_human" not in finding_columns:
                self.conn.execute("ALTER TABLE findings ADD COLUMN needs_human INTEGER NOT NULL DEFAULT 1")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def meta_get(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def meta_set(self, key: str, value: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self.conn.commit()

    def password_hash(self) -> str | None:
        return self.meta_get("password_hash")

    def set_password(self, password_hash: str) -> None:
        self.meta_set("password_hash", password_hash)

    def settings(self) -> dict:
        raw = self.meta_get("settings")
        base = {
            "provider": "opencode",
            "model": "",
            "provider_order": "opencode,ollama,openrouter,anthropic,openai,gemini",
            "opencode_product": "go",
            "sprites_provider": "ollama",
            "sprites_connection_id": "",
            "ollama_host": "http://127.0.0.1:11434",
            "github_org": "",
            "github_repo": "",
            "github_export": "",
            "notion_reports_database": "",
            "notion_tracker_database": "",
            "notion_programs_database": "",
            "notion_publish": "ask",
            "pinecone_index": "",
            "pinecone_embed_model": "multilingual-e5-large",
            "jev_model": "jev-latest",
        }
        if not raw:
            return base
        try:
            stored = json.loads(raw)
        except json.JSONDecodeError:
            return base
        base.update({key: stored[key] for key in base if key in stored})
        return base

    def save_settings(self, settings: dict) -> dict:
        current = self.settings()
        for key in current:
            if key in settings and settings[key] is not None:
                current[key] = str(settings[key])[:200]
        self.meta_set("settings", json.dumps(current))
        return current

    def set_secret(self, name: str, value: str) -> None:
        if name not in SECRET_NAMES:
            raise ValueError("Unknown secret name.")
        if not value:
            self.delete_secret(name)
            return
        token = self.fernet.encrypt(value.encode())
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO secrets(name, ciphertext, updated_at) VALUES(?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = excluded.updated_at
                """,
                (name, token, utcnow()),
            )
            self.conn.commit()

    def get_secret(self, name: str) -> str | None:
        row = self.conn.execute("SELECT ciphertext FROM secrets WHERE name = ?", (name,)).fetchone()
        if not row:
            return None
        try:
            return self.fernet.decrypt(bytes(row["ciphertext"])).decode()
        except InvalidToken:
            return None

    def secret_names(self) -> list[str]:
        rows = self.conn.execute("SELECT name FROM secrets ORDER BY name").fetchall()
        return [row["name"] for row in rows]

    def delete_secret(self, name: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
            self.conn.commit()

    def create_run(self, **fields) -> str:
        fields.setdefault("mode", "passive")
        fields.setdefault("attestation", "")
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO runs(id, created_at, target, program, intensity, status, provider, model, error, scope_json, source, notion, mode, attestation)
                VALUES(:id, :created_at, :target, :program, :intensity, :status, :provider, :model, '', :scope_json, :source, :notion, :mode, :attestation)
                """,
                fields,
            )
            self.conn.commit()
        return fields["id"]

    def get_run(self, run_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None

    def list_runs(self, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, created_at, target, program, intensity, status, provider, model, source FROM runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def active_run(self) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM runs WHERE status = 'running' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def set_notion(self, run_id: str, choice: str) -> None:
        if choice not in {"yes", "no", "ask"}:
            raise ValueError("Notion choice must be yes, no, or ask.")
        with self._lock:
            self.conn.execute("UPDATE runs SET notion = ? WHERE id = ?", (choice, run_id))
            self.conn.commit()

    def set_run_model(self, run_id: str, provider: str, model: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE runs SET provider = ?, model = ? WHERE id = ?",
                (provider[:80], model[:200], run_id),
            )
            self.conn.commit()

    def finish_run(self, run_id: str, status: str, error: str = "") -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE runs SET status = ?, error = ? WHERE id = ?",
                (status, error[:400], run_id),
            )
            self.conn.commit()

    def fail_stuck_runs(self) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE runs SET status = 'error', error = 'interrupted by restart' WHERE status = 'running'"
            )
            self.conn.commit()

    def event(self, run_id: str, level: str, message: str) -> int:
        with self._lock:
            cursor = self.conn.execute(
                "INSERT INTO events(run_id, ts, level, message) VALUES(?, ?, ?, ?)",
                (run_id, utcnow(), level, message[:500]),
            )
            self.conn.commit()
            return int(cursor.lastrowid)

    def events_after(self, run_id: str, after_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, level, message FROM events WHERE run_id = ? AND id > ? ORDER BY id",
            (run_id, after_id),
        ).fetchall()
        return [dict(row) for row in rows]

    def add_finding(self, **fields) -> None:
        fields.setdefault("confidence", "")
        fields.setdefault("repro", "")
        fields.setdefault("needs_human", 1)
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO findings(id, run_id, host, tool, severity, title, evidence, plain, created_at, jev, confidence, repro, needs_human)
                VALUES(:id, :run_id, :host, :tool, :severity, :title, :evidence, :plain, :created_at, :jev, :confidence, :repro, :needs_human)
                """,
                fields,
            )
            self.conn.commit()

    def findings(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY created_at",
            (run_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_finding(self, finding_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def set_finding_plain(self, finding_id: str, plain: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE findings SET plain = ? WHERE id = ?", (plain[:2000], finding_id))
            self.conn.commit()

    def set_finding_playbook(self, finding_id: str, playbook: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE findings SET playbook = ? WHERE id = ?", (playbook[:20000], finding_id))
            self.conn.commit()

    def set_run_playbook(self, run_id: str, playbook: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE runs SET playbook = ? WHERE id = ?", (playbook[:20000], run_id))
            self.conn.commit()

    def audit(self, action: str, target: str, decision: str, detail: str, run_id: str | None = None) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO audit(ts, run_id, action, target, decision, detail) VALUES(?, ?, ?, ?, ?, ?)",
                (utcnow(), run_id, action, target[:253], decision, detail[:800]),
            )
            self.conn.commit()

    def recent_audit(self, limit: int = 40) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, run_id, action, target, decision, detail FROM audit ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def add_terminal(self, run_id: str, command: str, status: str, output: str) -> int:
        with self._lock:
            cursor = self.conn.execute(
                "INSERT INTO terminal(run_id, ts, command, status, output) VALUES(?, ?, ?, ?, ?)",
                (run_id, utcnow(), command[:500], status[:40], output[:8000]),
            )
            self.conn.commit()
            return int(cursor.lastrowid)

    def terminal_lines(self, run_id: str, limit: int = 80) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, command, status, output FROM terminal WHERE run_id = ? ORDER BY id DESC LIMIT ?",
            (run_id, limit),
        ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def save_report(self, run_id: str, markdown: str) -> None:
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO reports(run_id, markdown, created_at) VALUES(?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET markdown = excluded.markdown, created_at = excluded.created_at
                """,
                (run_id, markdown, utcnow()),
            )
            self.conn.commit()

    def get_report(self, run_id: str) -> str | None:
        row = self.conn.execute("SELECT markdown FROM reports WHERE run_id = ?", (run_id,)).fetchone()
        return row["markdown"] if row else None
