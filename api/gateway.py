"""Gateway that applies authorization before synthetic execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from api.authorization import Decision, authorize
from api.storage import SQLiteStore


@dataclass
class GatewayRequest:
    user_id: str
    role: str
    action: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class GatewayResponse:
    decision: str
    action: str
    executed: bool
    reason: str
    result: dict[str, Any] | None = None
    approval_request: dict[str, Any] | None = None
    correlation_id: str | None = None


class SyntheticBackend:
    """Deliberately small persistent backend for security-control testing."""

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    @property
    def incidents(self) -> dict[str, dict[str, Any]]:
        """Compatibility view used by tests and demos."""
        return self.store.incidents_dict()

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action == "search_knowledge":
            return {
                "matches": [
                    "incident-response.md",
                    "credential-theft-runbook.md",
                ],
                "query": arguments["query"],
            }

        if action == "get_incident":
            return {"incident": self.store.get_incident(arguments["incident_id"])}

        if action == "add_incident_note":
            return {
                "incident": self.store.add_incident_note(
                    arguments["incident_id"], arguments["note"]
                )
            }

        if action == "update_incident_status":
            return {
                "incident": self.store.update_incident_status(
                    arguments["incident_id"], arguments["status"]
                )
            }

        raise RuntimeError(f"backend received unimplemented action: {action}")


class SecurityGateway:
    def __init__(
        self,
        store: SQLiteStore | None = None,
        backend: SyntheticBackend | None = None,
    ) -> None:
        self.store = store or SQLiteStore()
        self.backend = backend or SyntheticBackend(self.store)

    @property
    def audit_events(self) -> list[dict[str, Any]]:
        return self.store.list_audit_events()

    @property
    def approval_requests(self) -> list[dict[str, Any]]:
        return self.store.list_approvals()

    def _audit(
        self,
        *,
        request: GatewayRequest,
        decision: str,
        executed: bool,
        reason: str,
        correlation_id: str,
    ) -> None:
        self.store.append_audit(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "gateway_decision",
                "correlation_id": correlation_id,
                "user_id": request.user_id,
                "role": request.role,
                "action": request.action,
                "decision": decision,
                "executed": executed,
                "reason": reason,
            }
        )

    def handle(self, request: GatewayRequest) -> GatewayResponse:
        correlation_id = str(uuid4())
        auth = authorize(
            user_id=request.user_id,
            role=request.role,
            action=request.action,
            arguments=request.arguments,
        )

        if auth.decision is Decision.DENY:
            self._audit(
                request=request,
                decision=auth.decision.value,
                executed=False,
                reason=auth.reason,
                correlation_id=correlation_id,
            )
            return GatewayResponse(
                decision=auth.decision.value,
                action=request.action,
                executed=False,
                reason=auth.reason,
                correlation_id=correlation_id,
            )

        if auth.decision is Decision.HOLD_FOR_APPROVAL:
            approval = self.store.create_approval(
                requesting_user=request.user_id,
                requesting_role=request.role,
                action=request.action,
                arguments=dict(request.arguments),
                correlation_id=correlation_id,
            )
            self._audit(
                request=request,
                decision=auth.decision.value,
                executed=False,
                reason=auth.reason,
                correlation_id=correlation_id,
            )
            return GatewayResponse(
                decision=auth.decision.value,
                action=request.action,
                executed=False,
                reason=auth.reason,
                approval_request=approval,
                correlation_id=correlation_id,
            )

        result = self.backend.execute(request.action, request.arguments)
        self._audit(
            request=request,
            decision=auth.decision.value,
            executed=True,
            reason=auth.reason,
            correlation_id=correlation_id,
        )
        return GatewayResponse(
            decision=auth.decision.value,
            action=request.action,
            executed=True,
            reason=auth.reason,
            result=result,
            correlation_id=correlation_id,
        )


def response_to_dict(response: GatewayResponse) -> dict[str, Any]:
    return asdict(response)
