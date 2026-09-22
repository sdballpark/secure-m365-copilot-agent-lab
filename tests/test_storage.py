import sqlite3

from api.approvals import ApprovalService
from api.gateway import GatewayRequest, SecurityGateway
from api.storage import SQLiteStore


def make_request(gateway: SecurityGateway):
    return gateway.handle(
        GatewayRequest(
            user_id="tenant:requester",
            role="access_request_agent",
            action="request_account_disable",
            arguments={
                "target_user": "compromised@example.test",
                "justification": "Confirmed compromise requiring containment",
            },
        )
    )


def test_incident_state_survives_restart(tmp_path):
    db_path = tmp_path / "securelab.db"

    first = SecurityGateway(store=SQLiteStore(str(db_path)))
    first.handle(
        GatewayRequest(
            user_id="tenant:analyst",
            role="security_analyst_agent",
            action="add_incident_note",
            arguments={
                "incident_id": "INC-1001",
                "note": "Persistent investigation note.",
            },
        )
    )
    first.store.close()

    second = SecurityGateway(store=SQLiteStore(str(db_path)))
    incident = second.store.get_incident("INC-1001")

    assert incident is not None
    assert incident["notes"] == ["Persistent investigation note."]


def test_pending_approval_survives_restart(tmp_path):
    db_path = tmp_path / "securelab.db"

    first = SecurityGateway(store=SQLiteStore(str(db_path)))
    response = make_request(first)
    approval_id = response.approval_request["approval_id"]
    first.store.close()

    second = SecurityGateway(store=SQLiteStore(str(db_path)))
    pending = second.store.get_approval(approval_id)

    assert pending is not None
    assert pending["status"] == "pending"


def test_approved_execution_survives_restart(tmp_path):
    db_path = tmp_path / "securelab.db"

    gateway = SecurityGateway(store=SQLiteStore(str(db_path)))
    service = ApprovalService(gateway)
    response = make_request(gateway)

    service.decide(
        approval_id=response.approval_request["approval_id"],
        approver_user_id="tenant:approver",
        approver_role="human_approver",
        decision="approve",
        comment="Approved after evidence review.",
    )
    gateway.store.close()

    reopened = SQLiteStore(str(db_path))

    assert "compromised@example.test" in reopened.privileged_targets(
        "account_disabled"
    )


def test_audit_chain_validates(tmp_path):
    store = SQLiteStore(str(tmp_path / "audit.db"))
    gateway = SecurityGateway(store=store)

    gateway.handle(
        GatewayRequest(
            user_id="tenant:analyst",
            role="readonly_agent",
            action="get_incident",
            arguments={"incident_id": "INC-1001"},
        )
    )
    gateway.handle(
        GatewayRequest(
            user_id="tenant:analyst",
            role="readonly_agent",
            action="search_knowledge",
            arguments={"query": "credential theft"},
        )
    )

    verification = store.verify_audit_chain()

    assert verification["valid"] is True
    assert verification["count"] == 2
    assert len(verification["head_hash"]) == 64


def test_audit_chain_detects_row_tampering(tmp_path):
    db_path = tmp_path / "audit.db"
    store = SQLiteStore(str(db_path))
    gateway = SecurityGateway(store=store)

    gateway.handle(
        GatewayRequest(
            user_id="tenant:analyst",
            role="readonly_agent",
            action="get_incident",
            arguments={"incident_id": "INC-1001"},
        )
    )
    store.close()

    connection = sqlite3.connect(db_path)
    connection.execute(
        """
        UPDATE audit_events
        SET event_json = '{"tampered":true}'
        WHERE sequence = 1
        """
    )
    connection.commit()
    connection.close()

    reopened = SQLiteStore(str(db_path))
    verification = reopened.verify_audit_chain()

    assert verification["valid"] is False
    assert verification["failed_sequence"] == 1
