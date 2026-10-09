from typing import Annotated
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect

from app.config import get_settings
from app.db import get_session
from app.models import OAuthClient
from app.security import SCOPE_READ, SCOPE_WRITE

router = APIRouter()


async def registration_metadata(request: Request) -> object:
    try:
        return await request.json()
    except (ValueError, UnicodeError, ClientDisconnect):
        return None


@router.post("/register")
def register_client(
    metadata: Annotated[object, Depends(registration_metadata)],
    session: Annotated[Session, Depends(get_session)],
) -> JSONResponse:
    invalid = JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
    if not isinstance(metadata, dict):
        return invalid
    redirect_uris = metadata.get("redirect_uris")
    client_name = metadata.get("client_name", "")
    if (not isinstance(redirect_uris, list) or not redirect_uris
            or not isinstance(client_name, str) or "\x00" in client_name):
        return invalid
    for uri in redirect_uris:
        if (not isinstance(uri, str) or not uri or "\\" in uri
                or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                       for character in uri)):
            return invalid
        try:
            parsed = urlsplit(uri)
            port = parsed.port
            if (not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or "#" in uri
                    or (port is not None and port == 0)
                    or not (parsed.scheme == "https"
                            or (parsed.scheme == "http" and parsed.hostname == "localhost"))):
                return invalid
        except ValueError:
            return invalid
    oauth_client = OAuthClient(
        client_id=uuid4().hex, client_name=client_name, redirect_uris=redirect_uris,
    )
    try:
        session.add(oauth_client)
        session.commit()
    except SQLAlchemyError:
        session.rollback()
        return JSONResponse({"error": "server_error"}, status_code=500)
    return JSONResponse({
        "client_id": oauth_client.client_id,
        "client_name": oauth_client.client_name,
        "redirect_uris": oauth_client.redirect_uris,
        "token_endpoint_auth_method": "none",
    }, status_code=201)


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
        "scopes_supported": required_scopes(),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    })
