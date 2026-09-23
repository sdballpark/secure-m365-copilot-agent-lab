"""PostgreSQL persistence for Azure-hosted SecureLab runtime state."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

import psycopg
from psycopg.rows import dict_row

from api.storage import GENESIS_HASH, _json, _now


class PostgresStore:
    """Durable PostgreSQL-backed state for hosted lab deployments."""

    def __init__(
        self,
        *,
        host: str,
        database: str,
        user: str,
        password: str,
        port: int = 5432,
        sslmode: str = "require",
    ) -> None:
        self.host = host
        self.database = database
        self.user = user
        self.password = password
        self.port = port
        self.sslmode = sslmode
        self._init_schema()
        self._seed_lab_data()

    @classmethod
    def from_env(cls) -> "PostgresStore":
        required = {
            "host": os.getenv("SECURELAB_PGHOST"),
            "database": os.getenv("SECURELAB_PGDATABASE"),
            "user": os.getenv("SECURELAB_PGUSER"),
            "password": os.getenv("SECURELAB_PGPASSWORD"),
        }
        missing = [key for key, value in required.items() if not value]
        if missing:
            raise RuntimeError(
                "PostgreSQL selected but required settings are missing: "
                + ", ".join(f"SECURELAB_PG{key.upper()}" for key in missing)
            )

        return cls(
            host=required["host"] or "",
            database=required["database"] or "",
            user=required["user"] or "",
            password=required["password"] or "",
            port=int(os.getenv("SECURELAB_PGPORT", "5432")),
            sslmode=os.getenv("SECURELAB_PGSSLMODE", "require"),
        )

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(
            host=self.host,
            dbname=self.database,
            user=self.user,
            password=self.password,
            port=self.port,
            sslmode=self.sslmode,
            connect_timeout=10,
            row_factory=dict_row,
        )

    def _init_schema(self) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                owner TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS incident_notes (
                note_id BIGSERIAL PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                note TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
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
            )
            """,
            """
            CREATE SEQUENCE IF NOT EXISTS approval_number_seq START WITH 1
            """,
            """
            CREATE TABLE IF NOT EXISTS privileged_state (
                target_user TEXT PRIMARY KEY,
                account_disabled SMALLINT NOT NULL DEFAULT 0,
                privileged_group_removed SMALLINT NOT NULL DEFAULT 0,
                tokens_revoked SMALLINT NOT NULL DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence BIGSERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )
            """,
        )
        with self._connect() as connection:
            with connection.cursor() as cursor:
                for statement in statements:
                    cursor.execute(statement)

    def _seed_lab_data(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO incidents (incident_id, status, owner)
                VALUES (%s, %s, %s)
                ON CONFLICT (incident_id) DO NOTHING
                """,
                ("INC-1001", "investigating", "soc@example.test"),
            )

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT incident_id, status, owner
                FROM incidents
                WHERE incident_id = %s
                """,
                (incident_id,),
            ).fetchone()
            if row is None:
                return None
            notes = [
                item["note"]
                for item in connection.execute(
                    """
                    SELECT note FROM incident_notes
                    WHERE incident_id = %s
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

    def add_incident_note(self, incident_id: str, note: str) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO incidents (incident_id, status, owner)
                VALUES (%s, 'new', NULL)
                ON CONFLICT (incident_id) DO NOTHING
                """,
                (incident_id,),
            )
            connection.execute(
                """
                INSERT INTO incident_notes (incident_id, note, created_at)
                VALUES (%s, %s, %s)
                """,
                (incident_id, note, _now()),
            )
        return self.get_incident(incident_id) or {}

    def update_incident_status(self, incident_id: str, status: str) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO incidents (incident_id, status, owner)
                VALUES (%s, 'new', NULL)
                ON CONFLICT (incident_id) DO NOTHING
                """,
                (incident_id,),
            )
            connection.execute(
                "UPDATE incidents SET status = %s WHERE incident_id = %s",
                (status, incident_id),
            )
        return self.get_incident(incident_id) or {}

    def incidents_dict(self) -> dict[str, dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT incident_id FROM incidents ORDER BY incident_id"
            ).fetchall()
        return {
            row["incident_id"]: self.get_incident(row["incident_id"]) or {}
            for row in rows
        }

    def create_approval(
        self,
        *,
        requesting_user: str,
        requesting_role: str,
        action: str,
        arguments: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, Any]:
        created_at = _now()
        with self._connect() as connection:
            number = connection.execute(
                "SELECT nextval('approval_number_seq') AS value"
            ).fetchone()["value"]
            approval_id = f"APR-{int(number):04d}"
            connection.execute(
                """
                INSERT INTO approvals (
                    approval_id, status, requesting_user, requesting_role,
                    action, arguments_json, correlation_id, created_at
                )
                VALUES (%s, 'pending', %s, %s, %s, %s, %s, %s)
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
        return self.get_approval(approval_id) or {}

    @staticmethod
    def _approval_from_row(row: dict[str, Any]) -> dict[str, Any]:
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
        for key in (
            "approver_user",
            "approver_role",
            "approval_comment",
            "decided_at",
            "executed_at",
        ):
            if row[key] is not None:
                result[key] = row[key]
        if row["execution_result_json"] is not None:
            result["execution_result"] = json.loads(row["execution_result_json"])
        return result

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = %s",
                (approval_id,),
            ).fetchone()
        return None if row is None else self._approval_from_row(row)

    def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if status is None:
                rows = connection.execute(
                    "SELECT * FROM approvals ORDER BY approval_id"
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM approvals
                    WHERE status = %s
                    ORDER BY approval_id
                    """,
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
        with self._connect() as connection:
            row = connection.execute(
                """
                UPDATE approvals
                SET status = %s, approver_user = %s, approver_role = %s,
                    approval_comment = %s, decided_at = %s
                WHERE approval_id = %s AND status = 'pending'
                RETURNING *
                """,
                (
                    status,
                    approver_user,
                    approver_role,
                    comment,
                    _now(),
                    approval_id,
                ),
            ).fetchone()
        if row is None:
            return self.get_approval(approval_id) or {}
        return self._approval_from_row(row)

    def mark_approval_executed(
        self,
        approval_id: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                """
                UPDATE approvals
                SET status = 'executed',
                    executed_at = %s,
                    execution_result_json = %s
                WHERE approval_id = %s AND status = 'approved'
                RETURNING *
                """,
                (_now(), _json(result), approval_id),
            ).fetchone()
        if row is None:
            return self.get_approval(approval_id) or {}
        return self._approval_from_row(row)

    def execute_privileged(
        self,
        action: str,
        target_user: str,
    ) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO privileged_state (target_user)
                VALUES (%s)
                ON CONFLICT (target_user) DO NOTHING
                """,
                (target_user,),
            )
            if action == "request_account_disable":
                connection.execute(
                    """
                    UPDATE privileged_state
                    SET account_disabled = 1
                    WHERE target_user = %s
                    """,
                    (target_user,),
                )
                result = {"target_user": target_user, "account_disabled": True}
            elif action == "request_privileged_group_removal":
                connection.execute(
                    """
                    UPDATE privileged_state
                    SET privileged_group_removed = 1
                    WHERE target_user = %s
                    """,
                    (target_user,),
                )
                result = {
                    "target_user": target_user,
                    "privileged_group_membership_removed": True,
                }
            elif action == "request_token_revocation":
                connection.execute(
                    """
                    UPDATE privileged_state
                    SET tokens_revoked = 1
                    WHERE target_user = %s
                    """,
                    (target_user,),
                )
                result = {"target_user": target_user, "tokens_revoked": True}
            else:
                raise ValueError("unsupported privileged action")
        return result

    def privileged_targets(self, field: str) -> set[str]:
        columns = {
            "account_disabled",
            "privileged_group_removed",
            "tokens_revoked",
        }
        if field not in columns:
            raise ValueError("unsupported privileged state field")
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT target_user FROM privileged_state WHERE {field} = 1"
            ).fetchall()
        return {row["target_user"] for row in rows}

    def append_audit(self, event: dict[str, Any]) -> dict[str, Any]:
        event_copy = dict(event)
        event_copy.setdefault("timestamp", _now())
        with self._connect() as connection:
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtext('securelab_audit_chain'))"
            )
            previous = connection.execute(
                """
                SELECT event_hash FROM audit_events
                ORDER BY sequence DESC
                LIMIT 1
                """
            ).fetchone()
            prev_hash = previous["event_hash"] if previous else GENESIS_HASH
            canonical = _json(event_copy)
            event_hash = hashlib.sha256(
                (prev_hash + canonical).encode("utf-8")
            ).hexdigest()
            row = connection.execute(
                """
                INSERT INTO audit_events (
                    timestamp, event_json, prev_hash, event_hash
                )
                VALUES (%s, %s, %s, %s)
                RETURNING sequence
                """,
                (
                    event_copy["timestamp"],
                    canonical,
                    prev_hash,
                    event_hash,
                ),
            ).fetchone()
        return {
            "sequence": row["sequence"],
            **event_copy,
            "prev_hash": prev_hash,
            "event_hash": event_hash,
        }

    def list_audit_events(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
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
        with self._connect() as connection:
            rows = connection.execute(
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
        """No-op because PostgreSQL connections are short-lived per operation."""
