import re
from pathlib import Path
from typing import Annotated
from urllib.parse import parse_qs, quote
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect

from app.db import get_session
from app.models import User
from app.security import normalize_email, verify_password

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")


def current_user(request: Request, session: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not isinstance(user_id, str):
        return None
    try:
        parsed_id = UUID(user_id)
    except ValueError:
        return None
    return session.get(User, parsed_id)


def require_user(request: Request, session: Annotated[Session, Depends(get_session)]) -> User:
    user = current_user(request, session)
    if user is None:
        raise HTTPException(303, headers={"Location": "/login?next=" + quote(request.url.path, safe="")})
    return user


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/") -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="login.html", context={"next": next})


async def login_fields(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise HTTPException(415, "Expected a URL-encoded login form")
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > 65536:
                raise HTTPException(413, "Login form is too large")
            body.extend(chunk)
        encoded = body.decode("utf-8")
        if re.search(r"%(?![0-9a-fA-F]{2})", encoded):
            raise ValueError("Invalid percent encoding")
        fields = parse_qs(encoded, keep_blank_values=True, strict_parsing=True,
                          errors="strict", max_num_fields=3)
        if any(len(values) != 1 for values in fields.values()):
            raise ValueError("Duplicate form field")
    except (ClientDisconnect, UnicodeError, ValueError):
        raise HTTPException(400, "Malformed login form") from None
    form = {name: values[0] for name, values in fields.items()}
    if "\x00" in form.get("email", ""):
        raise HTTPException(400, "Malformed login form")
    if not form.get("email", "").strip() or not form.get("password"):
        raise HTTPException(422, "Email and password are required")
    return form


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    form: Annotated[dict[str, str], Depends(login_fields)],
) -> Response:
    email, password, next = form["email"], form["password"], form.get("next", "/")
    user = session.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"next": next, "error": "Invalid email or password"}, status_code=401,
        )
    request.session.clear()
    request.session["user_id"] = str(user.id)
    # Only local paths can be used as a post-login destination.
    if (not next.startswith("/") or next.startswith("//") or "\\" in next
            or any(ord(character) < 32 or ord(character) == 127 for character in next)):
        next = "/"
    return RedirectResponse(next, status_code=303)


@router.post("/logout")
def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
