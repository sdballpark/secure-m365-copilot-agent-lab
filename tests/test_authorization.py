from api.authorization import (
    DENIED_ACTIONS,
    Decision,
    authorize,
    exposed_actions_for_role,
)


def test_readonly_agent_can_read():
    result = authorize(
        user_id="analyst@example.test",
        role="readonly_agent",
        action="get_incident",
        arguments={"incident_id": "INC-1001"},
    )
    assert result.decision is Decision.ALLOW


def test_readonly_agent_cannot_write():
    result = authorize(
        user_id="analyst@example.test",
        role="readonly_agent",
        action="add_incident_note",
        arguments={"incident_id": "INC-1001", "note": "Reviewed sign-ins."},
    )
    assert result.decision is Decision.DENY


def test_security_analyst_can_use_bounded_write():
    result = authorize(
        user_id="analyst@example.test",
        role="security_analyst_agent",
        action="add_incident_note",
        arguments={"incident_id": "INC-1001", "note": "Reviewed sign-ins."},
    )
    assert result.decision is Decision.ALLOW


def test_privileged_action_is_held_for_approval():
    result = authorize(
        user_id="lead@example.test",
        role="access_request_agent",
        action="request_account_disable",
        arguments={
            "target_user": "compromised@example.test",
            "justification": "Confirmed credential compromise",
        },
    )
    assert result.decision is Decision.HOLD_FOR_APPROVAL


def test_agent_cannot_approve_its_own_request():
    result = authorize(
        user_id="lead@example.test",
        role="access_request_agent",
        action="approve_privileged_request",
        arguments={},
    )
    assert result.decision is Decision.DENY
    assert "not exposed" in result.reason


def test_denied_actions_are_never_exposed():
    actions = set(exposed_actions_for_role("access_request_agent"))
    assert actions.isdisjoint(DENIED_ACTIONS)


def test_unknown_action_fails_closed():
    result = authorize(
        user_id="analyst@example.test",
        role="access_request_agent",
        action="totally_new_powerful_action",
        arguments={},
    )
    assert result.decision is Decision.DENY
    assert "fail closed" in result.reason


def test_unknown_role_fails_closed():
    result = authorize(
        user_id="analyst@example.test",
        role="tenant_super_admin_agent",
        action="search_knowledge",
        arguments={"query": "incident response"},
    )
    assert result.decision is Decision.DENY


def test_malformed_incident_id_is_rejected():
    result = authorize(
        user_id="analyst@example.test",
        role="security_analyst_agent",
        action="add_incident_note",
        arguments={
            "incident_id": "INC-1001; DROP TABLE incidents;",
            "note": "test",
        },
    )
    assert result.decision is Decision.DENY


def test_invalid_status_is_rejected():
    result = authorize(
        user_id="analyst@example.test",
        role="security_analyst_agent",
        action="update_incident_status",
        arguments={"incident_id": "INC-1001", "status": "delete_everything"},
    )
    assert result.decision is Decision.DENY
