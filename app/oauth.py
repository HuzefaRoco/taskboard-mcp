from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.security import SCOPE_READ, SCOPE_WRITE

router = APIRouter()


def required_scopes() -> list[str]:
    return [SCOPE_READ, SCOPE_WRITE]


@router.get("/.well-known/oauth-protected-resource")
def protected_resource_metadata() -> JSONResponse:
    base = get_settings().public_base_url
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
        "scopes_supported": required_scopes(),
    })


@router.get("/.well-known/oauth-authorization-server")
def authorization_server_metadata() -> JSONResponse:
    base = get_settings().public_base_url
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": base + "/authorize",
        "token_endpoint": base + "/token",
        "registration_endpoint": base + "/register",
        "response_types_supported": ["code"],
        "scopes_supported": required_scopes() + ["offline_access"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    })
