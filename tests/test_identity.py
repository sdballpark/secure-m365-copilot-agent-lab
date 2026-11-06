import pytest

from api.identity import (
    CallerContext,
    EntraConfig,
    IdentityError,
    claims_to_context,
    resolve_internal_role,
)


CONFIG = EntraConfig(
    tenant_id="11111111-1111-1111-1111-111111111111",
    api_client_id="22222222-2222-2222-2222-222222222222",
    required_scope="access_as_user",
    allowed_client_ids=("33333333-3333-3333-3333-333333333333",),
)


def good_claims():
    return {
        "ver": "2.0",
        "tid": CONFIG.tenant_id,
        "oid": "44444444-4444-4444-4444-444444444444",
        "preferred_username": "analyst@example.test",
        "azp": "33333333-3333-3333-3333-333333333333",
        "scp": "access_as_user",
        "roles": ["SecureLab.SecurityAnalyst"],
    }


def test_role_mapping_uses_highest_authorized_role():
    role = resolve_internal_role(
        ["SecureLab.ReadOnly", "SecureLab.AccessRequest"]
    )
    assert role == "access_request_agent"


def test_unknown_role_claims_fail_closed():
    with pytest.raises(IdentityError):
        resolve_internal_role(["Global Administrator", "Made.Up.Role"])


def test_good_delegated_claims_create_immutable_context():
    context = claims_to_context(good_claims(), CONFIG)

    assert isinstance(context, CallerContext)
    assert context.role == "security_analyst_agent"
    assert context.user_id == (
        f"{CONFIG.tenant_id}:44444444-4444-4444-4444-444444444444"
    )
    assert context.username == "analyst@example.test"


def test_wrong_tenant_is_rejected():
    claims = good_claims()
    claims["tid"] = "99999999-9999-9999-9999-999999999999"

    with pytest.raises(IdentityError, match="tenant"):
        claims_to_context(claims, CONFIG)


def test_missing_required_scope_is_rejected():
    claims = good_claims()
    claims["scp"] = "profile.read"

    with pytest.raises(IdentityError, match="scope"):
        claims_to_context(claims, CONFIG)


def test_app_only_token_is_rejected():
    claims = good_claims()
    claims["idtyp"] = "app"
    claims.pop("scp")

    with pytest.raises(IdentityError, match="app-only"):
        claims_to_context(claims, CONFIG)


def test_unapproved_client_app_is_rejected():
    claims = good_claims()
    claims["azp"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    with pytest.raises(IdentityError, match="allowlisted"):
        claims_to_context(claims, CONFIG)


def test_missing_oid_is_rejected():
    claims = good_claims()
    claims.pop("oid")

    with pytest.raises(IdentityError, match="oid"):
        claims_to_context(claims, CONFIG)


def test_v1_token_is_rejected():
    claims = good_claims()
    claims["ver"] = "1.0"

    with pytest.raises(IdentityError, match="v2.0"):
        claims_to_context(claims, CONFIG)



def test_human_approver_role_maps_to_separate_control_plane_role():
    role = resolve_internal_role(["SecureLab.HumanApprover"])
    assert role == "human_approver"


def test_human_approver_role_takes_precedence_over_agent_roles():
    role = resolve_internal_role(
        ["SecureLab.AccessRequest", "SecureLab.HumanApprover"]
    )
    assert role == "human_approver"


def test_empty_client_allowlist_refuses_every_client():
    """An empty allowlist must refuse, not skip the check.

    Before the fix, `if config.allowed_client_ids and ...` short-circuited on an
    empty tuple, so any client application in the tenant was accepted.
    """
    open_config = EntraConfig(
        tenant_id=CONFIG.tenant_id,
        api_client_id=CONFIG.api_client_id,
        required_scope="access_as_user",
        allowed_client_ids=(),
    )
    with pytest.raises(IdentityError, match="no client applications are allowlisted"):
        claims_to_context(good_claims(), open_config)


@pytest.mark.parametrize("value", [None, "", " ", ", ,"])
def test_config_requires_a_client_allowlist(monkeypatch, value):
    from api.identity import config_from_env

    monkeypatch.setenv("ENTRA_TENANT_ID", CONFIG.tenant_id)
    monkeypatch.setenv("ENTRA_API_CLIENT_ID", CONFIG.api_client_id)
    if value is None:
        monkeypatch.delenv("ENTRA_ALLOWED_CLIENT_IDS", raising=False)
    else:
        monkeypatch.setenv("ENTRA_ALLOWED_CLIENT_IDS", value)

    with pytest.raises(IdentityError, match="ENTRA_ALLOWED_CLIENT_IDS"):
        config_from_env()


def test_config_accepts_a_populated_client_allowlist(monkeypatch):
    from api.identity import config_from_env

    monkeypatch.setenv("ENTRA_TENANT_ID", CONFIG.tenant_id)
    monkeypatch.setenv("ENTRA_API_CLIENT_ID", CONFIG.api_client_id)
    monkeypatch.setenv("ENTRA_ALLOWED_CLIENT_IDS", "33333333-3333-3333-3333-333333333333")
    assert config_from_env().allowed_client_ids == ("33333333-3333-3333-3333-333333333333",)
