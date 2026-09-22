"""SQLite persistence and tamper-evident append-only audit storage."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any


GENESIS_HASH = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class SQLiteStore:
    """Small persistence layer for the security lab.

    Tests default to an in-memory database. The API uses from_env(), which
    defaults to .local/securelab.db so state survives process restarts.
    """

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)

        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._init_schema()
        self._seed_lab_data()

    @classmethod
    def from_env(cls) -> "SQLiteStore":
        return cls(os.getenv("SECURELAB_DB_PATH", ".local/securelab.db"))

    def _init_schema(self) -> None:
        self.connection.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                owner TEXT
            );

            CREATE TABLE IF NOT EXISTS incident_notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
            );

            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                requesting_user TEXT NOT NULL,
                requesting_role TEXT NOT NULL,
                action TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                approver_user TEXT,
                approver_role TEXT,
                approval_comment TEXT,
                decided_at TEXT,
                executed_at TEXT,
                execution_result_json TEXT
            );

            CREATE TABLE IF NOT EXISTS privileged_state (
                target_user TEXT PRIMARY KEY,
                account_disabled INTEGER NOT NULL DEFAULT 0,
                privileged_group_removed INTEGER NOT NULL DEFAULT 0,
                tokens_revoked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    def _seed_lab_data(self) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO incidents (incident_id, status, owner)
            VALUES (?, ?, ?)
            """,
            ("INC-1001", "investigating", "soc@example.test"),
        )
        self.connection.commit()

    # ---------- Incident state ----------

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT incident_id, status, owner FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            return None

        notes = [
            item["note"]
            for item in self.connection.execute(
                """
                SELECT note FROM incident_notes
                WHERE incident_id = ?
                ORDER BY note_id
                """,
                (incident_id,),
            ).fetchall()
        ]
        return {
            "incident_id": row["incident_id"],
            "status": row["status"],
            "owner": row["owner"],
            "notes": notes,
        }

    def ensure_incident(self, incident_id: str) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO incidents (incident_id, status, owner)
            VALUES (?, 'new', NULL)
            """,
            (incident_id,),
        )
        self.connection.commit()

    def add_incident_note(self, incident_id: str, note: str) -> dict[str, Any]:
        self.ensure_incident(incident_id)
        self.connection.execute(
            """
            INSERT INTO incident_notes (incident_id, note, created_at)
            VALUES (?, ?, ?)
            """,
            (incident_id, note, _now()),
        )
        self.connection.commit()
        return self.get_incident(incident_id) or {}

    def update_incident_status(self, incident_id: str, status: str) -> dict[str, Any]:
        self.ensure_incident(incident_id)
        self.connection.execute(
            "UPDATE incidents SET status = ? WHERE incident_id = ?",
            (status, incident_id),
        )
        self.connection.commit()
        return self.get_incident(incident_id) or {}

    def incidents_dict(self) -> dict[str, dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT incident_id FROM incidents ORDER BY incident_id"
        ).fetchall()
        return {
            row["incident_id"]: self.get_incident(row["incident_id"]) or {}
            for row in rows
        }

    # ---------- Approval state ----------

    def _next_approval_id(self) -> str:
        rows = self.connection.execute(
            "SELECT approval_id FROM approvals"
        ).fetchall()
        numbers = []
        for row in rows:
            value = row["approval_id"]
            if value.startswith("APR-") and value[4:].isdigit():
                numbers.append(int(value[4:]))
        return f"APR-{(max(numbers, default=0) + 1):04d}"

    def create_approval(
        self,
        *,
        requesting_user: str,
        requesting_role: str,
        action: str,
        arguments: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, Any]:
        approval_id = self._next_approval_id()
        created_at = _now()
        self.connection.execute(
            """
            INSERT INTO approvals (
                approval_id, status, requesting_user, requesting_role,
                action, arguments_json, correlation_id, created_at
            )
            VALUES (?, 'pending', ?, ?, ?, ?, ?, ?)
            """,
            (
                approval_id,
                requesting_user,
                requesting_role,
                action,
                _json(arguments),
                correlation_id,
                created_at,
            ),
        )
        self.connection.commit()
        return self.get_approval(approval_id) or {}

    def _approval_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        result = {
            "approval_id": row["approval_id"],
            "status": row["status"],
            "requesting_user": row["requesting_user"],
            "requesting_role": row["requesting_role"],
            "action": row["action"],
            "arguments": json.loads(row["arguments_json"]),
            "correlation_id": row["correlation_id"],
            "created_at": row["created_at"],
        }
        optional = (
            "approver_user",
            "approver_role",
            "approval_comment",
            "decided_at",
            "executed_at",
        )
        for key in optional:
            if row[key] is not None:
                result[key] = row[key]

        if row["execution_result_json"] is not None:
            result["execution_result"] = json.loads(row["execution_result_json"])
        return result

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        return None if row is None else self._approval_from_row(row)

    def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        if status is None:
            rows = self.connection.execute(
                "SELECT * FROM approvals ORDER BY approval_id"
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM approvals WHERE status = ? ORDER BY approval_id",
                (status,),
            ).fetchall()
        return [self._approval_from_row(row) for row in rows]

    def decide_approval(
        self,
        *,
        approval_id: str,
        status: str,
        approver_user: str,
        approver_role: str,
        comment: str,
    ) -> dict[str, Any]:
        self.connection.execute(
            """
            UPDATE approvals
            SET status = ?, approver_user = ?, approver_role = ?,
                approval_comment = ?, decided_at = ?
            WHERE approval_id = ? AND status = 'pending'
            """,
            (
                status,
                approver_user,
                approver_role,
                comment,
                _now(),
                approval_id,
            ),
        )
        self.connection.commit()
        return self.get_approval(approval_id) or {}

    def mark_approval_executed(
        self,
        approval_id: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        self.connection.execute(
            """
            UPDATE approvals
            SET status = 'executed', executed_at = ?, execution_result_json = ?
            WHERE approval_id = ? AND status = 'approved'
            """,
            (_now(), _json(result), approval_id),
        )
        self.connection.commit()
        return self.get_approval(approval_id) or {}

    # ---------- Synthetic privileged state ----------

    def _ensure_privileged_target(self, target_user: str) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO privileged_state (target_user)
            VALUES (?)
            """,
            (target_user,),
        )

    def execute_privileged(
        self,
        action: str,
        target_user: str,
    ) -> dict[str, Any]:
        self._ensure_privileged_target(target_user)

        if action == "request_account_disable":
            self.connection.execute(
                """
                UPDATE privileged_state
                SET account_disabled = 1
                WHERE target_user = ?
                """,
                (target_user,),
            )
            result = {"target_user": target_user, "account_disabled": True}

        elif action == "request_privileged_group_removal":
            self.connection.execute(
                """
                UPDATE privileged_state
                SET privileged_group_removed = 1
                WHERE target_user = ?
                """,
                (target_user,),
            )
            result = {
                "target_user": target_user,
                "privileged_group_membership_removed": True,
            }

        elif action == "request_token_revocation":
            self.connection.execute(
                """
                UPDATE privileged_state
                SET tokens_revoked = 1
                WHERE target_user = ?
                """,
                (target_user,),
            )
            result = {"target_user": target_user, "tokens_revoked": True}

        else:
            raise ValueError("unsupported privileged action")

        self.connection.commit()
        return result

    def privileged_targets(self, field: str) -> set[str]:
        columns = {
            "account_disabled",
            "privileged_group_removed",
            "tokens_revoked",
        }
        if field not in columns:
            raise ValueError("unsupported privileged state field")

        rows = self.connection.execute(
            f"SELECT target_user FROM privileged_state WHERE {field} = 1"
        ).fetchall()
        return {row["target_user"] for row in rows}

    # ---------- Tamper-evident audit ----------

    def append_audit(self, event: dict[str, Any]) -> dict[str, Any]:
        previous = self.connection.execute(
            """
            SELECT event_hash FROM audit_events
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()
        prev_hash = previous["event_hash"] if previous else GENESIS_HASH

        event_copy = dict(event)
        event_copy.setdefault("timestamp", _now())
        canonical = _json(event_copy)
        event_hash = hashlib.sha256(
            (prev_hash + canonical).encode("utf-8")
        ).hexdigest()

        cursor = self.connection.execute(
            """
            INSERT INTO audit_events (
                timestamp, event_json, prev_hash, event_hash
            )
            VALUES (?, ?, ?, ?)
            """,
            (event_copy["timestamp"], canonical, prev_hash, event_hash),
        )
        self.connection.commit()

        return {
            "sequence": cursor.lastrowid,
            **event_copy,
            "prev_hash": prev_hash,
            "event_hash": event_hash,
        }

    def list_audit_events(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT sequence, event_json, prev_hash, event_hash
            FROM audit_events
            ORDER BY sequence
            """
        ).fetchall()
        events = []
        for row in rows:
            event = json.loads(row["event_json"])
            events.append(
                {
                    "sequence": row["sequence"],
                    **event,
                    "prev_hash": row["prev_hash"],
                    "event_hash": row["event_hash"],
                }
            )
        return events

    def verify_audit_chain(self) -> dict[str, Any]:
        rows = self.connection.execute(
            """
            SELECT sequence, event_json, prev_hash, event_hash
            FROM audit_events
            ORDER BY sequence
            """
        ).fetchall()

        expected_prev = GENESIS_HASH
        for row in rows:
            if row["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "count": len(rows),
                    "failed_sequence": row["sequence"],
                    "reason": "previous hash does not match chain head",
                }

            expected_hash = hashlib.sha256(
                (expected_prev + row["event_json"]).encode("utf-8")
            ).hexdigest()
            if row["event_hash"] != expected_hash:
                return {
                    "valid": False,
                    "count": len(rows),
                    "failed_sequence": row["sequence"],
                    "reason": "event hash mismatch",
                }

            expected_prev = row["event_hash"]

        return {
            "valid": True,
            "count": len(rows),
            "head_hash": expected_prev,
        }

    def close(self) -> None:
        self.connection.close()
