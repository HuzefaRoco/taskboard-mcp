import re
import secrets
from datetime import datetime, timedelta, timezone
from time import time
from typing import Annotated
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect

from app.config import get_settings
from app.db import get_session
from app.models import AuthorizationCode, OAuthClient
from app.security import SCOPE_READ, SCOPE_WRITE, new_token, token_hash
from app.web import current_user, templates

router = APIRouter()


async def authorize_fields(request: Request) -> dict[str, str]:
    if request.method == "GET":
        pairs = list(request.query_params.multi_items())
        if any(name in ("decision", "consent_token") for name, _ in pairs):
            raise HTTPException(400, "Reserved authorize parameter")
        if len({name for name, _ in pairs}) != len(pairs):
            raise HTTPException(400, "Duplicate authorize parameter")
        return dict(pairs)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise HTTPException(415, "Expected a URL-encoded consent form")
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > 65536:
                raise HTTPException(413, "Consent form is too large")
            body.extend(chunk)
        encoded = body.decode("utf-8")
        if re.search(r"%(?![0-9a-fA-F]{2})", encoded):
            raise ValueError("Invalid percent encoding")
        fields = parse_qs(encoded, keep_blank_values=True, strict_parsing=True,
                          errors="strict", max_num_fields=32)
        if any(len(values) != 1 for values in fields.values()):
            raise ValueError("Duplicate form field")
    except (ClientDisconnect, UnicodeError, ValueError):
        raise HTTPException(400, "Malformed consent form") from None
    return {name: values[0] for name, values in fields.items()}


@router.get("/authorize")
@router.post("/authorize")
def authorize(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    fields: Annotated[dict[str, str], Depends(authorize_fields)],
) -> Response:
    decision = fields.pop("decision", None)
    consent_token = fields.pop("consent_token", "")
    if any("\x00" in value for value in fields.values()):
        raise HTTPException(400, "Invalid authorize parameter")
    oauth_client = session.get(OAuthClient, fields.get("client_id", ""))
    redirect_uri = fields.get("redirect_uri", "")
    scope = fields.get("scope", "")
    if (oauth_client is None or fields.get("response_type") != "code"
            or redirect_uri not in oauth_client.redirect_uris
            or fields.get("code_challenge_method") != "S256"
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", fields.get("code_challenge", ""))
            or not scope.split() or not set(scope.split()).issubset(required_scopes())
            or not fields.get("resource")):
        raise HTTPException(400, "Invalid authorization request")
    user = current_user(request, session)
    if user is None:
        # Preserve the complete local URL so login's safe-next policy accepts it.
        query = request.url.query if request.method == "GET" else urlencode(fields)
        next_url = request.url.path + ("?" + query if query else "")
        return RedirectResponse("/login?next=" + quote(next_url, safe=""), status_code=303)
    if request.method == "GET":
        consent_token = new_token()
        request.session["oauth_consent"] = {
            "token_hash": token_hash(consent_token), "user_id": str(user.id),
            "parameters_hash": token_hash(urlencode(sorted(fields.items()))),
            "expires_at": time() + 600,
        }
        return templates.TemplateResponse(
            request=request, name="consent.html",
            context={"client_name": oauth_client.client_name,
                     "scopes": scope.split(), "fields": fields, "consent_token": consent_token},
            headers={"Cache-Control": "no-store"},
        )
    if decision not in ("approve", "deny"):
        raise HTTPException(400, "Invalid consent decision")
    consent = request.session.get("oauth_consent")
    if (not isinstance(consent, dict) or consent.get("user_id") != str(user.id)
            or consent.get("expires_at", 0) <= time()
            or not secrets.compare_digest(consent.get("token_hash", ""), token_hash(consent_token))
            or consent.get("parameters_hash") != token_hash(urlencode(sorted(fields.items())))):
        raise HTTPException(403, "Invalid or expired consent")
    del request.session["oauth_consent"]
    result = {"state": fields.get("state", "")}
    if decision == "deny":
        result["error"] = "access_denied"
    else:
        code = new_token()
        authorization_code = AuthorizationCode(
            code_hash=token_hash(code), client_id=oauth_client.client_id, user_id=user.id,
            redirect_uri=redirect_uri, scope=scope, code_challenge=fields["code_challenge"],
            code_challenge_method="S256", resource=fields["resource"],
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=600),
        )
        try:
            session.add(authorization_code)
            session.commit()
        except SQLAlchemyError:
            session.rollback()
            return JSONResponse({"error": "server_error"}, status_code=500)
        result["code"] = code
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(redirect_uri + separator + urlencode(result), status_code=303)


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
            # urlsplit separates components but does not validate their URI syntax.
            if (re.search(r"%(?![0-9A-Fa-f]{2})", uri)
                    or not re.fullmatch(
                        r"(?:[A-Za-z0-9._~!$&'()*+,;=%-]+|\[[A-Za-z0-9._~!$&'()*+,;=:%-]+\])"
                        r"(?::[0-9]+)?", parsed.netloc)
                    or not re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:@/%-]*", parsed.path)
                    or not re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:@/?%-]*", parsed.query)):
                return invalid
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
