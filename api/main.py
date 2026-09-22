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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/actions")
def actions(x_agent_role: str = Header(default="readonly_agent")) -> dict[str, Any]:
    return {
        "role": x_agent_role,
        "actions": exposed_actions_for_role(x_agent_role),
    }


@app.post("/actions/{action}")
def invoke_action(
    action: str,
    payload: ActionPayload,
    x_user_id: str = Header(...),
    x_agent_role: str = Header(default="readonly_agent"),
) -> dict[str, Any]:
    response = gateway.handle(
        GatewayRequest(
            user_id=x_user_id,
            role=x_agent_role,
            action=action,
            arguments=payload.arguments,
        )
    )
    return response_to_dict(response)
