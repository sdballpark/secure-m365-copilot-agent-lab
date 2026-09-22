"""FastAPI adapter for the deterministic security gateway."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from api.approvals import ApprovalError, ApprovalService
from api.authorization import exposed_actions_for_role
from api.gateway import GatewayRequest, SecurityGateway, response_to_dict
from api.identity import CallerContext, get_caller_context
from api.storage import SQLiteStore


app = FastAPI(
    title="Secure M365 Copilot Agent Lab API",
    version="0.3.0",
    description=(
        "Synthetic action API demonstrating Microsoft Entra token validation, "
        "deterministic authorization, persistent approval state, human approval "
        "boundaries, and tamper-evident audit evidence."
    ),
)

store = SQLiteStore.from_env()
gateway = SecurityGateway(store=store)
approval_service = ApprovalService(gateway)


class ActionPayload(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


class KnowledgeSearchPayload(BaseModel):
    query: str


class IncidentNotePayload(BaseModel):
    note: str


class AccountDisableRequestPayload(BaseModel):
    target_user: str
    justification: str


class ApprovalDecisionPayload(BaseModel):
    decision: str
    comment: str


def _invoke(
    *,
    action: str,
    arguments: dict[str, Any],
    caller: CallerContext,
) -> dict[str, Any]:
    response = gateway.handle(
        GatewayRequest(
            user_id=caller.user_id,
            role=caller.role,
            action=action,
            arguments=arguments,
        )
    )
    return response_to_dict(response)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/actions")
def actions(
    caller: CallerContext = Depends(get_caller_context),
) -> dict[str, Any]:
    return {
        "role": caller.role,
        "actions": exposed_actions_for_role(caller.role),
    }


@app.post("/knowledge/search")
def search_knowledge(
    payload: KnowledgeSearchPayload,
    caller: CallerContext = Depends(get_caller_context),
) -> dict[str, Any]:
    return _invoke(
        action="search_knowledge",
        arguments={"query": payload.query},
        caller=caller,
    )


@app.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    caller: CallerContext = Depends(get_caller_context),
) -> dict[str, Any]:
    return _invoke(
        action="get_incident",
        arguments={"incident_id": incident_id},
        caller=caller,
    )


@app.post("/incidents/{incident_id}/notes")
def add_incident_note(
    incident_id: str,
    payload: IncidentNotePayload,
    caller: CallerContext = Depends(get_caller_context),
) -> dict[str, Any]:
    return _invoke(
        action="add_incident_note",
        arguments={"incident_id": incident_id, "note": payload.note},
        caller=caller,
    )


@app.post("/privileged/account-disable-requests")
def request_account_disable(
    payload: AccountDisableRequestPayload,
    caller: CallerContext = Depends(get_caller_context),
) -> dict[str, Any]:
    return _invoke(
        action="request_account_disable",
        arguments={
            "target_user": payload.target_user,
            "justification": payload.justification,
        },
        caller=caller,
    )


@app.post("/actions/{action}")
def invoke_action(
    action: str,
    payload: ActionPayload,
    caller: CallerContext = Depends(get_caller_context),
) -> dict[str, Any]:
    return _invoke(
        action=action,
        arguments=payload.arguments,
        caller=caller,
    )


@app.get("/approvals/pending")
def pending_approvals(
    caller: CallerContext = Depends(get_caller_context),
) -> dict[str, Any]:
    if caller.role != "human_approver":
        return {"error": "human approver role required", "approvals": []}

    return {"approvals": approval_service.list_pending()}


@app.post("/approvals/{approval_id}/decision")
def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionPayload,
    caller: CallerContext = Depends(get_caller_context),
) -> dict[str, Any]:
    try:
        result = approval_service.decide(
            approval_id=approval_id,
            approver_user_id=caller.user_id,
            approver_role=caller.role,
            decision=payload.decision,
            comment=payload.comment,
        )
    except ApprovalError as exc:
        return {
            "approval_id": approval_id,
            "status": "rejected",
            "executed": False,
            "reason": str(exc),
        }

    return {
        "approval_id": result.approval_id,
        "status": result.status,
        "executed": result.executed,
        "reason": result.reason,
        "result": result.result,
    }


@app.get("/audit/verify")
def verify_audit_chain(
    caller: CallerContext = Depends(get_caller_context),
) -> dict[str, Any]:
    if caller.role != "human_approver":
        return {"valid": False, "error": "human approver role required"}

    return store.verify_audit_chain()
