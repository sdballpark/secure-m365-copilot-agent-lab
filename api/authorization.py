"""Deterministic authorization for agent actions.

The language model may request an action. This module decides whether that
request is allowed, denied, or must be held for independent human approval.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Mapping


class ActionTier(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    PRIVILEGED = "PRIVILEGED"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    HOLD_FOR_APPROVAL = "HOLD_FOR_APPROVAL"


@dataclass(frozen=True)
class ActionDefinition:
    name: str
    tier: ActionTier
    minimum_role: str


@dataclass(frozen=True)
class AuthorizationResult:
    decision: Decision
    action: str
    tier: ActionTier | None
    reason: str


ROLE_RANK = {
    "readonly_agent": 0,
    "security_analyst_agent": 1,
    "access_request_agent": 2,
}

ACTION_REGISTRY = {
    "search_knowledge": ActionDefinition(
        "search_knowledge", ActionTier.READ, "readonly_agent"
    ),
    "get_incident": ActionDefinition(
        "get_incident", ActionTier.READ, "readonly_agent"
    ),
    "add_incident_note": ActionDefinition(
        "add_incident_note", ActionTier.WRITE, "security_analyst_agent"
    ),
    "update_incident_status": ActionDefinition(
        "update_incident_status", ActionTier.WRITE, "security_analyst_agent"
    ),
    "request_account_disable": ActionDefinition(
        "request_account_disable", ActionTier.PRIVILEGED, "access_request_agent"
    ),
    "request_privileged_group_removal": ActionDefinition(
        "request_privileged_group_removal",
        ActionTier.PRIVILEGED,
        "access_request_agent",
    ),
    "request_token_revocation": ActionDefinition(
        "request_token_revocation", ActionTier.PRIVILEGED, "access_request_agent"
    ),
}

# These operations are intentionally absent from the exposed action registry.
DENIED_ACTIONS = {
    "approve_privileged_request",
    "grant_global_admin",
    "disable_audit_logging",
    "delete_audit_log",
    "export_directory_external",
}

_INCIDENT_ID = re.compile(r"^INC-[0-9]{4,8}$")
_SAFE_IDENTITY = re.compile(r"^[A-Za-z0-9._@-]{3,128}$")
_ALLOWED_STATUSES = {"new", "investigating", "contained", "closed"}


def exposed_actions_for_role(role: str) -> list[str]:
    """Return only actions the role may request.

    Denied operations never appear because they are not registered.
    """

    if role not in ROLE_RANK:
        return []

    rank = ROLE_RANK[role]
    return sorted(
        name
        for name, action in ACTION_REGISTRY.items()
        if rank >= ROLE_RANK[action.minimum_role]
    )


def _validate_arguments(action: str, arguments: Mapping[str, Any]) -> str | None:
    """Return an error string when arguments are invalid."""

    if not isinstance(arguments, Mapping):
        return "arguments must be an object"

    if action in {"get_incident", "add_incident_note", "update_incident_status"}:
        incident_id = arguments.get("incident_id")
        if not isinstance(incident_id, str) or not _INCIDENT_ID.fullmatch(incident_id):
            return "incident_id must match INC-####"

    if action == "add_incident_note":
        note = arguments.get("note")
        if not isinstance(note, str) or not note.strip():
            return "note is required"
        if len(note) > 500:
            return "note exceeds 500 characters"

    if action == "update_incident_status":
        status = arguments.get("status")
        if status not in _ALLOWED_STATUSES:
            return f"status must be one of {sorted(_ALLOWED_STATUSES)}"

    if action in {
        "request_account_disable",
        "request_privileged_group_removal",
        "request_token_revocation",
    }:
        target_user = arguments.get("target_user")
        if (
            not isinstance(target_user, str)
            or not _SAFE_IDENTITY.fullmatch(target_user)
        ):
            return "target_user is invalid"

        justification = arguments.get("justification")
        if not isinstance(justification, str) or len(justification.strip()) < 10:
            return "justification must contain at least 10 characters"

    if action == "search_knowledge":
        query = arguments.get("query")
        if not isinstance(query, str) or not query.strip():
            return "query is required"
        if len(query) > 300:
            return "query exceeds 300 characters"

    return None


def authorize(
    *,
    user_id: str,
    role: str,
    action: str,
    arguments: Mapping[str, Any],
) -> AuthorizationResult:
    """Make a deterministic authorization decision.

    Unknown identities, roles, actions, and malformed arguments fail closed.
    """

    if not isinstance(user_id, str) or not _SAFE_IDENTITY.fullmatch(user_id):
        return AuthorizationResult(
            Decision.DENY, action, None, "requesting identity is invalid"
        )

    if role not in ROLE_RANK:
        return AuthorizationResult(
            Decision.DENY, action, None, "unrecognized role; fail closed"
        )

    if action in DENIED_ACTIONS:
        return AuthorizationResult(
            Decision.DENY,
            action,
            None,
            "capability is deliberately not exposed to the agent",
        )

    definition = ACTION_REGISTRY.get(action)
    if definition is None:
        return AuthorizationResult(
            Decision.DENY, action, None, "unknown action; fail closed"
        )

    if ROLE_RANK[role] < ROLE_RANK[definition.minimum_role]:
        return AuthorizationResult(
            Decision.DENY,
            action,
            definition.tier,
            f"role {role} is not authorized for {definition.tier.value} actions",
        )

    validation_error = _validate_arguments(action, arguments)
    if validation_error:
        return AuthorizationResult(
            Decision.DENY, action, definition.tier, validation_error
        )

    if definition.tier is ActionTier.PRIVILEGED:
        return AuthorizationResult(
            Decision.HOLD_FOR_APPROVAL,
            action,
            definition.tier,
            "privileged action requires independent human approval",
        )

    return AuthorizationResult(
        Decision.ALLOW,
        action,
        definition.tier,
        "request is authorized by deterministic policy",
    )
