"""Interactive human-approval client for the Secure M365 Copilot Agent Lab.

Uses OAuth 2.0 authorization-code flow with PKCE and a loopback redirect.
No client secret is used and access tokens are never persisted.

Required environment variables:
  SECURELAB_TENANT_ID
  SECURELAB_APPROVAL_CLIENT_ID
  SECURELAB_APPROVAL_SCOPE
  SECURELAB_API_BASE_URL

Examples:
  python scripts/securelab_approver.py pending
  python scripts/securelab_approver.py approve APR-0001 --comment "Independent review completed"
  python scripts/securelab_approver.py deny APR-0001 --comment "Request not approved"
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class _CallbackState:
    code: str | None = None
    error: str | None = None
    error_description: str | None = None
    received_state: str | None = None


def _make_handler(callback: _CallbackState):
    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)

            callback.code = params.get("code", [None])[0]
            callback.error = params.get("error", [None])[0]
            callback.error_description = params.get("error_description", [None])[0]
            callback.received_state = params.get("state", [None])[0]

            if callback.code:
                message = (
                    "SecureLab approver sign-in completed. "
                    "You may close this browser window and return to PowerShell."
                )
                status = 200
            else:
                message = (
                    "SecureLab approver sign-in failed. "
                    "Return to PowerShell for the error details."
                )
                status = 400

            body = (
                "<!doctype html><html><body style='font-family:Segoe UI,Arial,sans-serif;"
                "max-width:720px;margin:60px auto'><h2>"
                + message
                + "</h2></body></html>"
            ).encode("utf-8")

            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return CallbackHandler


def acquire_token() -> str:
    tenant_id = _required_env("SECURELAB_TENANT_ID")
    client_id = _required_env("SECURELAB_APPROVAL_CLIENT_ID")
    scope = _required_env("SECURELAB_APPROVAL_SCOPE")

    callback = _CallbackState()
    server = HTTPServer(("127.0.0.1", 0), _make_handler(callback))
    port = server.server_address[1]
    redirect_uri = f"http://localhost:{port}"

    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())

    authorize_url = (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?"
        + urllib.parse.urlencode(
            {
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "response_mode": "query",
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "prompt": "select_account",
            }
        )
    )

    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    print("Opening Microsoft sign-in in your browser...")
    print("Sign in with the independent SecureLab Human Approver account.")
    if not webbrowser.open(authorize_url):
        print("Browser did not open automatically. Open this URL manually:")
        print(authorize_url)

    thread.join(timeout=300)
    server.server_close()

    if thread.is_alive():
        raise SystemExit("Timed out waiting for browser sign-in.")

    if callback.error:
        detail = callback.error_description or callback.error
        raise SystemExit(f"Microsoft sign-in failed: {detail}")

    if not callback.code:
        raise SystemExit("Microsoft sign-in did not return an authorization code.")

    if callback.received_state != state:
        raise SystemExit("OAuth state validation failed.")

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_body = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "grant_type": "authorization_code",
            "code": callback.code,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_verifier": code_verifier,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        token_url,
        data=token_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            token_response = json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Token exchange failed ({exc.code}): {body}") from exc

    access_token = token_response.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise SystemExit("Token response did not contain an access token.")

    return access_token


def api_request(method: str, path: str, token: str, payload: dict[str, Any] | None = None) -> Any:
    base_url = _required_env("SECURELAB_API_BASE_URL").rstrip("/")
    data = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        base_url + path,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"SecureLab API returned HTTP {exc.code}: {body}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureLab independent human approval client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("pending", help="List pending privileged requests")

    for command in ("approve", "deny"):
        decision_parser = subparsers.add_parser(command, help=f"{command.title()} a pending request")
        decision_parser.add_argument("approval_id")
        decision_parser.add_argument(
            "--comment",
            required=True,
            help="Independent human review comment (minimum 5 characters)",
        )

    args = parser.parse_args()
    token = acquire_token()

    if args.command == "pending":
        result = api_request("GET", "/approvals/pending", token)
    else:
        if len(args.comment.strip()) < 5:
            raise SystemExit("Approval comment must contain at least 5 characters.")
        result = api_request(
            "POST",
            f"/approvals/{urllib.parse.quote(args.approval_id, safe='')}/decision",
            token,
            {
                "decision": args.command,
                "comment": args.comment,
            },
        )

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
