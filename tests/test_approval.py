import pytest

from api.approvals import ApprovalError, ApprovalService
from api.gateway import GatewayRequest, SecurityGateway


def create_privileged_request(gateway: SecurityGateway, user_id="requester:test"):
    return gateway.handle(
        GatewayRequest(
            user_id=user_id,
            role="access_request_agent",
            action="request_account_disable",
            arguments={
                "target_user": "compromised@example.test",
                "justification": "Confirmed compromise in synthetic incident",
            },
        )
    )


def test_privileged_request_does_not_execute_before_approval():
    gateway = SecurityGateway()
    service = ApprovalService(gateway)

    response = create_privileged_request(gateway)

    assert response.decision == "HOLD_FOR_APPROVAL"
    assert response.executed is False
    assert service.executor.disabled_accounts == set()


def test_independent_approver_can_approve_and_execute():
    gateway = SecurityGateway()
    service = ApprovalService(gateway)
    response = create_privileged_request(gateway)

    decision = service.decide(
        approval_id=response.approval_request["approval_id"],
        approver_user_id="approver:test",
        approver_role="human_approver",
        decision="approve",
        comment="Evidence reviewed and containment approved.",
    )

    assert decision.status == "executed"
    assert decision.executed is True
    assert "compromised@example.test" in service.executor.disabled_accounts


def test_self_approval_is_blocked():
    gateway = SecurityGateway()
    service = ApprovalService(gateway)
    response = create_privileged_request(gateway, user_id="same:test")

    with pytest.raises(ApprovalError, match="own request"):
        service.decide(
            approval_id=response.approval_request["approval_id"],
            approver_user_id="same:test",
            approver_role="human_approver",
            decision="approve",
            comment="Trying to self approve.",
        )

    assert service.executor.disabled_accounts == set()


def test_agent_role_cannot_approve():
    gateway = SecurityGateway()
    service = ApprovalService(gateway)
    response = create_privileged_request(gateway)

    with pytest.raises(ApprovalError, match="independent approver"):
        service.decide(
            approval_id=response.approval_request["approval_id"],
            approver_user_id="analyst:test",
            approver_role="access_request_agent",
            decision="approve",
            comment="Attempt from agent role.",
        )


def test_denial_closes_request_without_execution():
    gateway = SecurityGateway()
    service = ApprovalService(gateway)
    response = create_privileged_request(gateway)

    decision = service.decide(
        approval_id=response.approval_request["approval_id"],
        approver_user_id="approver:test",
        approver_role="human_approver",
        decision="deny",
        comment="Evidence is insufficient.",
    )

    assert decision.status == "denied"
    assert decision.executed is False
    assert service.executor.disabled_accounts == set()


def test_request_cannot_be_decided_twice():
    gateway = SecurityGateway()
    service = ApprovalService(gateway)
    response = create_privileged_request(gateway)
    approval_id = response.approval_request["approval_id"]

    service.decide(
        approval_id=approval_id,
        approver_user_id="approver:test",
        approver_role="human_approver",
        decision="deny",
        comment="First decision is final.",
    )

    with pytest.raises(ApprovalError, match="no longer pending"):
        service.decide(
            approval_id=approval_id,
            approver_user_id="second-approver:test",
            approver_role="human_approver",
            decision="approve",
            comment="Second decision attempt.",
        )


def test_execution_is_written_to_audit_chain():
    gateway = SecurityGateway()
    service = ApprovalService(gateway)
    response = create_privileged_request(gateway)

    service.decide(
        approval_id=response.approval_request["approval_id"],
        approver_user_id="approver:test",
        approver_role="human_approver",
        decision="approve",
        comment="Approved after evidence review.",
    )

    assert any(
        event.get("event_type") == "privileged_request_executed"
        and event.get("executed") is True
        for event in gateway.audit_events
    )
