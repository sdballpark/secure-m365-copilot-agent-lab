"""Microsoft Entra ID access-token validation and caller authorization context.

This module is the identity boundary between Microsoft 365 / Copilot and the
deterministic action gateway. Model-supplied identity or role values are never
accepted as authorization input.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os
from typing import Any, Mapping

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


ROLE_CLAIM_MAP = {
    "SecureLab.ReadOnly": "readonly_agent",
    "SecureLab.SecurityAnalyst": "security_analyst_agent",
    "SecureLab.AccessRequest": "access_request_agent",
}

ROLE_RANK = {
    "readonly_agent": 0,
    "security_analyst_agent": 1,
    "access_request_agent": 2,
}


class IdentityError(ValueError):
    """Raised when token claims fail identity or authorization policy."""


@dataclass(frozen=True)
class EntraConfig:
    tenant_id: str
    api_client_id: str
    required_scope: str = "access_as_user"
    allowed_client_ids: tuple[str, ...] = ()

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def jwks_url(self) -> str:
        return (
            f"https://login.microsoftonline.com/{self.tenant_id}"
            "/discovery/v2.0/keys"
        )


@dataclass(frozen=True)
class CallerContext:
    """Trusted identity context derived only from a validated access token."""

    user_id: str
    tenant_id: str
    object_id: str
    username: str | None
    client_id: str
    role: str
    scopes: tuple[str, ...]


def _split_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def config_from_env() -> EntraConfig:
    tenant_id = os.getenv("ENTRA_TENANT_ID", "").strip()
    api_client_id = os.getenv("ENTRA_API_CLIENT_ID", "").strip()
    required_scope = os.getenv("ENTRA_REQUIRED_SCOPE", "access_as_user").strip()
    allowed_client_ids = _split_csv(os.getenv("ENTRA_ALLOWED_CLIENT_IDS"))

    missing = []
    if not tenant_id:
        missing.append("ENTRA_TENANT_ID")
    if not api_client_id:
        missing.append("ENTRA_API_CLIENT_ID")
    if not required_scope:
        missing.append("ENTRA_REQUIRED_SCOPE")

    if missing:
        raise IdentityError(
            "missing required Entra configuration: " + ", ".join(missing)
        )

    return EntraConfig(
        tenant_id=tenant_id,
        api_client_id=api_client_id,
        required_scope=required_scope,
        allowed_client_ids=allowed_client_ids,
    )


def resolve_internal_role(role_claims: Any) -> str:
    """Map explicit SecureLab app-role claims to the highest internal role."""

    if not isinstance(role_claims, (list, tuple)):
        raise IdentityError("token does not contain an authorized SecureLab app role")

    mapped = [
        ROLE_CLAIM_MAP[claim]
        for claim in role_claims
        if isinstance(claim, str) and claim in ROLE_CLAIM_MAP
    ]
    if not mapped:
        raise IdentityError("token does not contain an authorized SecureLab app role")

    return max(mapped, key=lambda role: ROLE_RANK[role])


def claims_to_context(
    claims: Mapping[str, Any],
    config: EntraConfig,
) -> CallerContext:
    """Validate authorization-relevant claims after JWT cryptographic validation."""

    tenant_id = claims.get("tid")
    object_id = claims.get("oid")
    token_version = claims.get("ver")
    client_id = claims.get("azp") or claims.get("appid")
    idtyp = claims.get("idtyp")
    scopes = tuple(str(claims.get("scp", "")).split())

    if token_version != "2.0":
        raise IdentityError("only Microsoft identity platform v2.0 access tokens are accepted")

    if tenant_id != config.tenant_id:
        raise IdentityError("token tenant does not match configured tenant")

    if not isinstance(object_id, str) or not object_id:
        raise IdentityError("token is missing immutable object identifier (oid)")

    if idtyp == "app" or not scopes:
        raise IdentityError("app-only tokens are not accepted by this delegated-user lab API")

    if config.required_scope not in scopes:
        raise IdentityError(
            f"token is missing required delegated scope: {config.required_scope}"
        )

    if not isinstance(client_id, str) or not client_id:
        raise IdentityError("token is missing authorized client identifier")

    if config.allowed_client_ids and client_id not in config.allowed_client_ids:
        raise IdentityError("calling client application is not allowlisted")

    role = resolve_internal_role(claims.get("roles"))
    username = claims.get("preferred_username")
    if not isinstance(username, str):
        username = None

    return CallerContext(
        user_id=f"{tenant_id}:{object_id}",
        tenant_id=tenant_id,
        object_id=object_id,
        username=username,
        client_id=client_id,
        role=role,
        scopes=scopes,
    )


class EntraTokenValidator:
    """Validate Microsoft Entra v2 access tokens for this API."""

    def __init__(self, config: EntraConfig) -> None:
        self.config = config
        self.jwks_client = jwt.PyJWKClient(config.jwks_url)

    def validate(self, token: str) -> CallerContext:
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.config.api_client_id,
                issuer=self.config.issuer,
                options={
                    "require": [
                        "aud",
                        "exp",
                        "iat",
                        "iss",
                        "nbf",
                        "oid",
                        "tid",
                        "ver",
                    ]
                },
            )
        except jwt.PyJWTError as exc:
            raise IdentityError("access token validation failed") from exc

        return claims_to_context(claims, self.config)


_bearer = HTTPBearer(auto_error=False)


@lru_cache
def get_token_validator() -> EntraTokenValidator:
    return EntraTokenValidator(config_from_env())


def get_caller_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> CallerContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Bearer access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return get_token_validator().validate(credentials.credentials)
    except IdentityError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
