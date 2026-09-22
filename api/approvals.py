"""Independent human approval workflow for privileged synthetic actions.

The Copilot/agent tool surface can create approval requests, but approval itself
is not an agent action. Approval requires a separately authorized human caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from api.gateway import SecurityGateway


class ApprovalError(ValueError):
    """Raised when an approval operation violates separation-of-duties policy."""


@dataclass(frozen=True)
class ApprovalDecision:
    approval_id: str
    status: str
    executed: bool
    reason: str
    result: dict[str, Any] | None = None


class PrivilegedExecutor:
    """Synthetic privileged executor reachable only after approval."""

    ALLOWED_ACTIONS = {
        "request_account_disable",
        "request_privileged_group_removal",
        "request_token_revocation",
    }

    def __init__(self) -> None:
        self.disabled_accounts: set[str] = set()
        self.removed_privileged_memberships: set[str] = set()
        self.revoked_tokens: set[str] = set()

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action not in self.ALLOWED_ACTIONS:
            raise ApprovalError("privileged executor received non-allowlisted action")

        target_user = arguments["target_user"]

        if action == "request_account_disable":
            self.disabled_accounts.add(target_user)
            return {"target_user": target_user, "account_disabled": True}

        if action == "request_privileged_group_removal":
            self.removed_privileged_memberships.add(target_user)
            return {
                "target_user": target_user,
                "privileged_group_membership_removed": True,
            }

        if action == "request_token_revocation":
            self.revoked_tokens.add(target_user)
            return {"target_user": target_user, "tokens_revoked": True}

        raise ApprovalError("unsupported privileged action")


class ApprovalService:
    def __init__(
        self,
        gateway: SecurityGateway,
        executor: PrivilegedExecutor | None = None,
    ) -> None:
        self.gateway = gateway
        self.executor = executor or PrivilegedExecutor()
        self.approval_audit: list[dict[str, Any]] = []

    def _find(self, approval_id: str) -> dict[str, Any]:
        for request in self.gateway.approval_requests:
            if request["approval_id"] == approval_id:
                return request
        raise ApprovalError("approval request not found")

    def list_pending(self) -> list[dict[str, Any]]:
        return [
            dict(request)
            for request in self.gateway.approval_requests
            if request["status"] == "pending"
        ]

    def decide(
        self,
        *,
        approval_id: str,
        approver_user_id: str,
        approver_role: str,
        decision: Literal["approve", "deny"],
        comment: str,
    ) -> ApprovalDecision:
        if approver_role != "human_approver":
            raise ApprovalError("caller is not authorized as an independent approver")

        request = self._find(approval_id)

        if request["status"] != "pending":
            raise ApprovalError("approval request is no longer pending")

        if request["requesting_user"] == approver_user_id:
            raise ApprovalError("requester cannot approve or deny their own request")

        if decision not in {"approve", "deny"}:
            raise ApprovalError("decision must be approve or deny")

        if not isinstance(comment, str) or len(comment.strip()) < 5:
            raise ApprovalError("approval comment must contain at least 5 characters")

        timestamp = datetime.now(timezone.utc).isoformat()
        request["approver_user"] = approver_user_id
        request["approver_role"] = approver_role
        request["approval_comment"] = comment
        request["decided_at"] = timestamp

        if decision == "deny":
            request["status"] = "denied"
            event = {
                "timestamp": timestamp,
                "event_type": "privileged_request_denied",
                "approval_id": approval_id,
                "requesting_user": request["requesting_user"],
                "approver_user": approver_user_id,
                "action": request["action"],
                "executed": False,
                "correlation_id": request["correlation_id"],
            }
            self.approval_audit.append(event)
            self.gateway.audit_events.append(event)
            return ApprovalDecision(
                approval_id=approval_id,
                status="denied",
                executed=False,
                reason="independent human approver denied the request",
            )

        request["status"] = "approved"
        result = self.executor.execute(request["action"], request["arguments"])
        request["status"] = "executed"
        request["executed_at"] = datetime.now(timezone.utc).isoformat()
        request["execution_result"] = result

        event = {
            "timestamp": request["executed_at"],
            "event_type": "privileged_request_executed",
            "approval_id": approval_id,
            "requesting_user": request["requesting_user"],
            "approver_user": approver_user_id,
            "action": request["action"],
            "executed": True,
            "correlation_id": request["correlation_id"],
        }
        self.approval_audit.append(event)
        self.gateway.audit_events.append(event)

        return ApprovalDecision(
            approval_id=approval_id,
            status="executed",
            executed=True,
            reason="independent human approval completed before execution",
            result=result,
        )
