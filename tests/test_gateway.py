from api.gateway import GatewayRequest, SecurityGateway


def test_allowed_read_executes_and_is_audited():
    gateway = SecurityGateway()
    response = gateway.handle(
        GatewayRequest(
            user_id="analyst@example.test",
            role="readonly_agent",
            action="get_incident",
            arguments={"incident_id": "INC-1001"},
        )
    )

    assert response.decision == "ALLOW"
    assert response.executed is True
    assert len(gateway.audit_events) == 1
    assert gateway.audit_events[0]["executed"] is True


def test_denied_write_does_not_execute():
    gateway = SecurityGateway()
    response = gateway.handle(
        GatewayRequest(
            user_id="analyst@example.test",
            role="readonly_agent",
            action="add_incident_note",
            arguments={"incident_id": "INC-1001", "note": "Should not execute"},
        )
    )

    assert response.decision == "DENY"
    assert response.executed is False
    assert gateway.backend.incidents["INC-1001"]["notes"] == []


def test_privileged_action_creates_approval_but_does_not_execute():
    gateway = SecurityGateway()
    response = gateway.handle(
        GatewayRequest(
            user_id="lead@example.test",
            role="access_request_agent",
            action="request_privileged_group_removal",
            arguments={
                "target_user": "compromised@example.test",
                "justification": "Incident INC-1001 confirmed compromise",
            },
        )
    )

    assert response.decision == "HOLD_FOR_APPROVAL"
    assert response.executed is False
    assert response.approval_request is not None
    assert response.approval_request["status"] == "pending"
    assert len(gateway.approval_requests) == 1


def test_self_approval_request_never_executes():
    gateway = SecurityGateway()
    response = gateway.handle(
        GatewayRequest(
            user_id="lead@example.test",
            role="access_request_agent",
            action="approve_privileged_request",
            arguments={"approval_id": "APR-0001"},
        )
    )

    assert response.decision == "DENY"
    assert response.executed is False


def test_write_changes_only_bounded_synthetic_state():
    gateway = SecurityGateway()
    response = gateway.handle(
        GatewayRequest(
            user_id="analyst@example.test",
            role="security_analyst_agent",
            action="add_incident_note",
            arguments={
                "incident_id": "INC-1001",
                "note": "Sign-in review complete.",
            },
        )
    )

    assert response.decision == "ALLOW"
    assert response.executed is True
    assert gateway.backend.incidents["INC-1001"]["notes"] == [
        "Sign-in review complete."
    ]
