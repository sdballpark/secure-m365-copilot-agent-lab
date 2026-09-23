"""Storage abstraction and runtime backend selection for SecureLab."""

from __future__ import annotations

import os
from typing import Any, Protocol

from api.storage import SQLiteStore


class StorageBackend(Protocol):
    """Interface shared by local SQLite and hosted PostgreSQL backends."""

    def get_incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def add_incident_note(self, incident_id: str, note: str) -> dict[str, Any]: ...
    def update_incident_status(
        self, incident_id: str, status: str
    ) -> dict[str, Any]: ...
    def incidents_dict(self) -> dict[str, dict[str, Any]]: ...

    def create_approval(
        self,
        *,
        requesting_user: str,
        requesting_role: str,
        action: str,
        arguments: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, Any]: ...
    def get_approval(self, approval_id: str) -> dict[str, Any] | None: ...
    def list_approvals(
        self, status: str | None = None
    ) -> list[dict[str, Any]]: ...
    def decide_approval(
        self,
        *,
        approval_id: str,
        status: str,
        approver_user: str,
        approver_role: str,
        comment: str,
    ) -> dict[str, Any]: ...
    def mark_approval_executed(
        self, approval_id: str, result: dict[str, Any]
    ) -> dict[str, Any]: ...

    def execute_privileged(
        self, action: str, target_user: str
    ) -> dict[str, Any]: ...
    def privileged_targets(self, field: str) -> set[str]: ...

    def append_audit(self, event: dict[str, Any]) -> dict[str, Any]: ...
    def list_audit_events(self) -> list[dict[str, Any]]: ...
    def verify_audit_chain(self) -> dict[str, Any]: ...
    def close(self) -> None: ...


def store_from_env() -> StorageBackend:
    """Select PostgreSQL for hosted runtime when configured, else SQLite."""

    if os.getenv("SECURELAB_PGHOST"):
        from api.postgres_storage import PostgresStore

        return PostgresStore.from_env()

    return SQLiteStore.from_env()
