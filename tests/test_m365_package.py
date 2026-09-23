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
    auth = plugin["runtimes"][0]["auth"]
    assert auth["type"] == "OAuthPluginVault"
    assert auth["reference_id"] == "${{SECURELAB_SSO_AUTH_ID}}"

def test_openapi_delegated_sso_scope():
    with (APP / "apiSpecificationFile" / "openapi.yaml").open(encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    scope = "${{SECURELAB_SSO_APP_ID_URI}}/access_as_user"
    assert spec["security"] == [{"OAuth2": [scope]}]
    assert scope in spec["components"]["securitySchemes"]["OAuth2"]["flows"]["authorizationCode"]["scopes"]

def test_aad_manifest_roles_and_token_store_preauth():
    manifest = load_json(ROOT / "aad.manifest.json")
    assert manifest["signInAudience"] == "AzureADMyOrg"
    assert manifest["api"]["requestedAccessTokenVersion"] == 2
    assert manifest["identifierUris"] == ["${{SECURELAB_SSO_APP_ID_URI}}"]
    preauth = manifest["api"]["preAuthorizedApplications"]
    assert preauth[0]["appId"] == "ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b"
    assert "c8bafb85-17bb-45b0-87d6-5362d71243e6" in preauth[0]["delegatedPermissionIds"]
    assert manifest["web"]["redirectUris"] == [
        "https://teams.microsoft.com/api/platform/v1.0/oAuthConsentRedirect"
    ]
    assert {r["value"] for r in manifest["appRoles"]} == {
        "SecureLab.ReadOnly",
        "SecureLab.SecurityAnalyst",
        "SecureLab.AccessRequest",
        "SecureLab.HumanApprover",
    }

def test_lifecycle_uses_microsoft_entra_sso_without_client_secret():
    with (ROOT / "m365agents.yml").open(encoding="utf-8") as f:
        lifecycle = yaml.safe_load(f)
    assert lifecycle["version"] == "v1.11"
    provision = lifecycle["provision"]
    aad = next(x for x in provision if x["uses"] == "aadApp/create")
    oauth = next(x for x in provision if x["uses"] == "oauth/register")
    assert aad["with"]["generateClientSecret"] is False
    assert aad["with"]["generateServicePrincipal"] is True
    assert oauth["with"]["identityProvider"] == "MicrosoftEntra"
    assert oauth["with"]["flow"] == "authorizationCode"
    assert oauth["with"]["baseUrl"] == "${{API_BASE_URL}}"
    assert oauth["writeToEnvironmentFile"]["configurationId"] == "SECURELAB_SSO_AUTH_ID"
    assert oauth["writeToEnvironmentFile"]["applicationIdUri"] == "SECURELAB_SSO_APP_ID_URI"
