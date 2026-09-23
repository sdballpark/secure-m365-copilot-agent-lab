"""Independent human approval workflow for privileged synthetic actions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from api.gateway import SecurityGateway
from api.storage_backend import StorageBackend


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

    def __init__(self, store: StorageBackend) -> None:
        self.store = store

    @property
    def disabled_accounts(self) -> set[str]:
        return self.store.privileged_targets("account_disabled")

    @property
    def removed_privileged_memberships(self) -> set[str]:
        return self.store.privileged_targets("privileged_group_removed")

    @property
    def revoked_tokens(self) -> set[str]:
        return self.store.privileged_targets("tokens_revoked")

    def execute(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if action not in self.ALLOWED_ACTIONS:
            raise ApprovalError("privileged executor received non-allowlisted action")

        return self.store.execute_privileged(action, arguments["target_user"])


class ApprovalService:
    def __init__(
        self,
        gateway: SecurityGateway,
        executor: PrivilegedExecutor | None = None,
    ) -> None:
        self.gateway = gateway
        self.store = gateway.store
        self.executor = executor or PrivilegedExecutor(self.store)

    @property
    def approval_audit(self) -> list[dict[str, Any]]:
        return [
            event
            for event in self.store.list_audit_events()
            if event.get("event_type", "").startswith("privileged_request_")
        ]

    def _find(self, approval_id: str) -> dict[str, Any]:
        request = self.store.get_approval(approval_id)
        if request is None:
            raise ApprovalError("approval request not found")
        return request

    def list_pending(self) -> list[dict[str, Any]]:
        return self.store.list_approvals(status="pending")

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

        if decision == "deny":
            request = self.store.decide_approval(
                approval_id=approval_id,
                status="denied",
                approver_user=approver_user_id,
                approver_role=approver_role,
                comment=comment,
            )
            self.store.append_audit(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "privileged_request_denied",
                    "approval_id": approval_id,
                    "requesting_user": request["requesting_user"],
                    "approver_user": approver_user_id,
                    "action": request["action"],
                    "executed": False,
                    "correlation_id": request["correlation_id"],
                }
            )
            return ApprovalDecision(
                approval_id=approval_id,
                status="denied",
                executed=False,
                reason="independent human approver denied the request",
            )

        request = self.store.decide_approval(
            approval_id=approval_id,
            status="approved",
            approver_user=approver_user_id,
            approver_role=approver_role,
            comment=comment,
        )
        result = self.executor.execute(request["action"], request["arguments"])
        request = self.store.mark_approval_executed(approval_id, result)

        self.store.append_audit(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "privileged_request_executed",
                "approval_id": approval_id,
                "requesting_user": request["requesting_user"],
                "approver_user": approver_user_id,
                "action": request["action"],
                "executed": True,
                "correlation_id": request["correlation_id"],
            }
        )

        return ApprovalDecision(
            approval_id=approval_id,
            status="executed",
            executed=True,
            reason="independent human approval completed before execution",
            result=result,
        )
