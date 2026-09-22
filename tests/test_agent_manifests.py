import json
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
AGENT = ROOT / "agent" / "declarativeAgent.json"
PLUGIN = ROOT / "agent" / "security-actions-plugin.json"
OPENAPI = ROOT / "api" / "openapi.yaml"

DENIED_FUNCTION_NAMES = {
    "approvePrivilegedRequest",
    "grantGlobalAdmin",
    "disableAuditLogging",
    "deleteAuditLog",
    "exportDirectoryExternal",
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_declarative_agent_uses_current_schema():
    agent = load_json(AGENT)
    assert agent["version"] == "v1.8"
    assert "/v1.8/" in agent["$schema"]


def test_sharepoint_knowledge_is_explicitly_scoped():
    agent = load_json(AGENT)
    capabilities = agent["capabilities"]
    sharepoint = next(
        capability
        for capability in capabilities
        if capability["name"] == "OneDriveAndSharePoint"
    )
    urls = [item["url"] for item in sharepoint["items_by_url"]]
    assert urls
    assert all(url.startswith("https://") for url in urls)


def test_agent_references_security_plugin():
    agent = load_json(AGENT)
    action_files = {action["file"] for action in agent["actions"]}
    assert "security-actions-plugin.json" in action_files


def test_plugin_uses_current_schema():
    plugin = load_json(PLUGIN)
    assert plugin["schema_version"] == "v2.4"


def test_plugin_does_not_expose_denied_capabilities():
    plugin = load_json(PLUGIN)
    function_names = {function["name"] for function in plugin["functions"]}
    assert function_names.isdisjoint(DENIED_FUNCTION_NAMES)


def test_plugin_function_names_match_openapi_operation_ids():
    plugin = load_json(PLUGIN)
    function_names = {function["name"] for function in plugin["functions"]}

    with OPENAPI.open("r", encoding="utf-8") as handle:
        spec = yaml.safe_load(handle)

    operation_ids = {
        operation["operationId"]
        for path_item in spec["paths"].values()
        for method, operation in path_item.items()
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }

    assert function_names == operation_ids


def test_plugin_requires_oauth_not_anonymous_runtime():
    plugin = load_json(PLUGIN)
    runtime = plugin["runtimes"][0]
    assert runtime["auth"]["type"] == "OAuthPluginVault"
    assert runtime["auth"].get("reference_id")


def test_state_changing_functions_are_marked_resource_updates():
    plugin = load_json(PLUGIN)
    functions = {function["name"]: function for function in plugin["functions"]}

    for name in {"addIncidentNote", "requestAccountDisable"}:
        handling = functions[name]["capabilities"]["security_info"]["data_handling"]
        assert "ResourceStateUpdate" in handling


def test_privileged_function_is_request_not_direct_execution():
    plugin = load_json(PLUGIN)
    function_names = {function["name"] for function in plugin["functions"]}
    assert "requestAccountDisable" in function_names
    assert "disableAccount" not in function_names
