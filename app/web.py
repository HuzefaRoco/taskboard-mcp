from pathlib import Path
from typing import Annotated
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

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


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/",
) -> Response:
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
