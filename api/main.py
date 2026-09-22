"""FastAPI adapter for the deterministic security gateway."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header
from pydantic import BaseModel, Field

from api.authorization import exposed_actions_for_role
from api.gateway import GatewayRequest, SecurityGateway, response_to_dict


app = FastAPI(
    title="Secure M365 Copilot Agent Lab API",
    version="0.1.0",
    description=(
        "Synthetic action API demonstrating deterministic authorization, "
        "human approval boundaries, and audit evidence for AI agents."
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
    x_user_id: str,
    x_agent_role: str,
) -> dict[str, Any]:
    response = gateway.handle(
        GatewayRequest(
            user_id=x_user_id,
            role=x_agent_role,
            action=action,
            arguments=arguments,
        )
    )
    return response_to_dict(response)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/actions")
def actions(x_agent_role: str = Header(default="readonly_agent")) -> dict[str, Any]:
    return {
        "role": x_agent_role,
        "actions": exposed_actions_for_role(x_agent_role),
    }


@app.post("/knowledge/search")
def search_knowledge(
    payload: KnowledgeSearchPayload,
    x_user_id: str = Header(...),
    x_agent_role: str = Header(default="readonly_agent"),
) -> dict[str, Any]:
    return _invoke(
        action="search_knowledge",
        arguments={"query": payload.query},
        x_user_id=x_user_id,
        x_agent_role=x_agent_role,
    )


@app.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    x_user_id: str = Header(...),
    x_agent_role: str = Header(default="readonly_agent"),
) -> dict[str, Any]:
    return _invoke(
        action="get_incident",
        arguments={"incident_id": incident_id},
        x_user_id=x_user_id,
        x_agent_role=x_agent_role,
    )


@app.post("/incidents/{incident_id}/notes")
def add_incident_note(
    incident_id: str,
    payload: IncidentNotePayload,
    x_user_id: str = Header(...),
    x_agent_role: str = Header(default="readonly_agent"),
) -> dict[str, Any]:
    return _invoke(
        action="add_incident_note",
        arguments={"incident_id": incident_id, "note": payload.note},
        x_user_id=x_user_id,
        x_agent_role=x_agent_role,
    )


@app.post("/privileged/account-disable-requests")
def request_account_disable(
    payload: AccountDisableRequestPayload,
    x_user_id: str = Header(...),
    x_agent_role: str = Header(default="readonly_agent"),
) -> dict[str, Any]:
    return _invoke(
        action="request_account_disable",
        arguments={
            "target_user": payload.target_user,
            "justification": payload.justification,
        },
        x_user_id=x_user_id,
        x_agent_role=x_agent_role,
    )


@app.post("/actions/{action}")
def invoke_action(
    action: str,
    payload: ActionPayload,
    x_user_id: str = Header(...),
    x_agent_role: str = Header(default="readonly_agent"),
) -> dict[str, Any]:
    return _invoke(
        action=action,
        arguments=payload.arguments,
        x_user_id=x_user_id,
        x_agent_role=x_agent_role,
    )
