"""FastAPI adapter for the deterministic security gateway."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from api.authorization import exposed_actions_for_role
from api.gateway import GatewayRequest, SecurityGateway, response_to_dict
from api.identity import CallerContext, get_caller_context


app = FastAPI(
    title="Secure M365 Copilot Agent Lab API",
    version="0.2.0",
    description=(
        "Synthetic action API demonstrating Microsoft Entra token validation, "
        "deterministic authorization, human approval boundaries, and audit evidence."
    ),
)

gateway = SecurityGateway()


class ActionPayload(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


class KnowledgeSearchPayload(BaseModel):
    query: str


class IncidentNotePayload(BaseModel):
    note: str


class AccountDisableRequestPayload(BaseModel):
    target_user: str
    justification: str


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
