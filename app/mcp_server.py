from collections.abc import Callable
from contextvars import ContextVar
from typing import Literal
from uuid import UUID

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from app import tasks
from app.config import get_settings
from app.db import SessionLocal
from app.security import SCOPE_READ, SCOPE_WRITE, resolve_access_token

authenticated_user_id: ContextVar[UUID] = ContextVar("authenticated_user_id")
authenticated_scopes: ContextVar[frozenset[str]] = ContextVar("authenticated_scopes")


def _require_scope(scope: str) -> None:
    if scope not in authenticated_scopes.get(frozenset()):
        raise ToolError(f"Missing required scope: {scope}")


def build_mcp_server(get_user_id: Callable[[], UUID]) -> MCPServer:
    server = MCPServer("taskboard")
    read_meta = {"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_READ]}]}
    write_meta = {"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_WRITE]}]}

    @server.tool(meta=write_meta)
    def add_task(title: str) -> dict[str, str]:
        """Create a task."""
        _require_scope(SCOPE_WRITE)
        try:
            with SessionLocal.begin() as session:
                task = tasks.add_task(session, get_user_id(), title)
                return {"id": str(task.id), "title": task.title, "status": task.status}
        except SQLAlchemyError as exc:
            raise ToolError("Task operation failed") from exc

    @server.tool(meta=read_meta)
    def list_tasks(status: Literal["open", "completed"] | None = None) -> dict[str, list[dict[str, str]]]:
        """List tasks, optionally filtered by status."""
        _require_scope(SCOPE_READ)
        try:
            with SessionLocal() as session:
                return {"tasks": [
                    {"id": str(task.id), "title": task.title, "status": task.status}
                    for task in tasks.list_tasks(session, get_user_id(), status)
                ]}
        except SQLAlchemyError as exc:
            raise ToolError("Task operation failed") from exc

    @server.tool(meta=write_meta)
    def complete_task(task_id: UUID) -> dict[str, str]:
        """Complete a task."""
        _require_scope(SCOPE_WRITE)
        try:
            with SessionLocal.begin() as session:
                task = tasks.complete_task(session, get_user_id(), task_id)
                return {"id": str(task.id), "title": task.title, "status": task.status}
        except tasks.TaskNotFound as exc:
            raise ToolError(f"Task not found: {task_id}") from exc
        except SQLAlchemyError as exc:
            raise ToolError("Task operation failed") from exc

    return server


def _resolve_auth(raw_token: str, resource: str) -> tuple[UUID, frozenset[str]] | None:
    with SessionLocal() as session:
        token = resolve_access_token(session, raw_token, resource)
        return (token.user_id, frozenset(token.scope.split())) if token is not None else None


class AuthenticatedMCP:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        base = get_settings().public_base_url
        authorization = Headers(scope=scope).getlist("authorization")
        parts = authorization[0].split() if len(authorization) == 1 else []
        auth = None
        if len(parts) == 2 and parts[0].lower() == "bearer":
            try:
                auth = await run_in_threadpool(_resolve_auth, parts[1], base)
            except SQLAlchemyError:
                await JSONResponse({"error": "server_error"}, status_code=503)(scope, receive, send)
                return
        if auth is None:
            await JSONResponse({"error": "invalid_token"}, status_code=401, headers={
                "WWW-Authenticate": (
                    f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource", '
                    f'scope="{SCOPE_READ} {SCOPE_WRITE}"'
                ),
            })(scope, receive, send)
            return

        user_id, scopes = auth
        context_token = authenticated_user_id.set(user_id)
        scope_token = authenticated_scopes.set(scopes)
        try:
            await scope["app"].state.mcp_app(scope, receive, send)
        finally:
            authenticated_scopes.reset(scope_token)
            authenticated_user_id.reset(context_token)
