import json
from pathlib import Path
import yaml

ROOT = Path(__file__).parents[1]
APP = ROOT / "appPackage"

def load_json(path):
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)

def test_app_manifest():
    manifest = load_json(APP / "manifest.json")
    assert manifest["manifestVersion"] == "1.30"
    assert manifest["permissions"] == ["identity"]
    assert manifest["copilotAgents"]["declarativeAgents"][0]["file"] == "declarativeAgent.json"

def test_agent_manifest():
    agent = load_json(APP / "declarativeAgent.json")
    assert agent["version"] == "v1.8"
    cap = next(x for x in agent["capabilities"] if x["name"] == "OneDriveAndSharePoint")
    assert cap["items_by_url"] == [{"url": "${{SHAREPOINT_SITE_URL}}"}]

def test_plugin_has_no_approval_function():
    plugin = load_json(APP / "ai-plugin.json")
    names = {x["name"] for x in plugin["functions"]}
    assert plugin["schema_version"] == "v2.4"
    assert "approvePrivilegedRequest" not in names
    assert "disableAccount" not in names
    assert "requestAccountDisable" in names

def test_openapi_delegated_oauth():
    with (APP / "apiSpecificationFile" / "openapi.yaml").open(encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    scope = "api://${{AAD_APP_CLIENT_ID}}/access_as_user"
    assert spec["security"] == [{"OAuth2": [scope]}]
    assert scope in spec["components"]["securitySchemes"]["OAuth2"]["flows"]["authorizationCode"]["scopes"]

def test_aad_manifest_roles():
    manifest = load_json(ROOT / "aad.manifest.json")
    assert manifest["signInAudience"] == "AzureADMyOrg"
    assert manifest["api"]["requestedAccessTokenVersion"] == 2
    assert {r["value"] for r in manifest["appRoles"]} == {
        "SecureLab.ReadOnly",
        "SecureLab.SecurityAnalyst",
        "SecureLab.AccessRequest",
        "SecureLab.HumanApprover",
    }

def test_lifecycle_uses_v111_pkce_and_no_client_secret():
    with (ROOT / "m365agents.yml").open(encoding="utf-8") as f:
        lifecycle = yaml.safe_load(f)
    assert lifecycle["version"] == "v1.11"
    provision = lifecycle["provision"]
    aad = next(x for x in provision if x["uses"] == "aadApp/create")
    oauth = next(x for x in provision if x["uses"] == "oauth/register")
    assert aad["with"]["generateClientSecret"] is False
    assert aad["with"]["generateServicePrincipal"] is True
    assert oauth["with"]["isPKCEEnabled"] is True
    assert oauth["with"]["targetAudience"] == "HomeTenant"
