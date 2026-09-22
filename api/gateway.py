"""Gateway that applies authorization before synthetic execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from api.authorization import Decision, authorize


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
    """Deliberately small backend for security-control testing."""

    def __init__(self) -> None:
        self.incidents = {
            "INC-1001": {
                "incident_id": "INC-1001",
                "status": "investigating",
                "owner": "soc@example.test",
                "notes": [],
            }
        }

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
            incident = self.incidents.get(arguments["incident_id"])
            return {"incident": incident}

        if action == "add_incident_note":
            incident = self.incidents.setdefault(
                arguments["incident_id"],
                {
                    "incident_id": arguments["incident_id"],
                    "status": "new",
                    "owner": None,
                    "notes": [],
                },
            )
            incident["notes"].append(arguments["note"])
            return {"incident": incident}

        if action == "update_incident_status":
            incident = self.incidents.setdefault(
                arguments["incident_id"],
                {
                    "incident_id": arguments["incident_id"],
                    "status": "new",
                    "owner": None,
                    "notes": [],
                },
            )
            incident["status"] = arguments["status"]
            return {"incident": incident}

        raise RuntimeError(f"backend received unimplemented action: {action}")


class SecurityGateway:
    def __init__(self, backend: SyntheticBackend | None = None) -> None:
        self.backend = backend or SyntheticBackend()
        self.audit_events: list[dict[str, Any]] = []
        self.approval_requests: list[dict[str, Any]] = []

    def _audit(
        self,
        *,
        request: GatewayRequest,
        decision: str,
        executed: bool,
        reason: str,
        correlation_id: str,
    ) -> None:
        self.audit_events.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
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
            approval = {
                "approval_id": f"APR-{len(self.approval_requests) + 1:04d}",
                "status": "pending",
                "requesting_user": request.user_id,
                "requesting_role": request.role,
                "action": request.action,
                "arguments": dict(request.arguments),
                "correlation_id": correlation_id,
            }
            self.approval_requests.append(approval)
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
