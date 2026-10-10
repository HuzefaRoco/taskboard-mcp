from collections.abc import Callable
from contextvars import ContextVar
from typing import Literal
from uuid import UUID

from mcp.server.mcpserver import MCPServer
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from app.config import get_settings
from app.db import SessionLocal
from app.security import SCOPE_READ, SCOPE_WRITE, resolve_access_token

authenticated_user_id: ContextVar[UUID] = ContextVar("authenticated_user_id")


def build_mcp_server(get_user_id: Callable[[], UUID]) -> MCPServer:
    server = MCPServer("taskboard")
    read_meta = {"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_READ]}]}
    write_meta = {"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_WRITE]}]}

    # shortcut: identity-only stubs, replace with scoped task operations in Task 12.
    @server.tool(meta=write_meta)
    def add_task(title: str) -> dict[str, str]:
        """Create a task."""
        return {"user_id": str(get_user_id())}

    @server.tool(meta=read_meta)
    def list_tasks(status: Literal["open", "completed"] | None = None) -> dict[str, str]:
        """List tasks, optionally filtered by status."""
        return {"user_id": str(get_user_id())}

    @server.tool(meta=write_meta)
    def complete_task(task_id: str) -> dict[str, str]:
        """Complete a task."""
        return {"user_id": str(get_user_id())}

    return server


def _resolve_user_id(raw_token: str, resource: str) -> UUID | None:
    with SessionLocal() as session:
        token = resolve_access_token(session, raw_token, resource)
        return token.user_id if token is not None else None


class AuthenticatedMCP:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        base = get_settings().public_base_url
        authorization = Headers(scope=scope).getlist("authorization")
        parts = authorization[0].split() if len(authorization) == 1 else []
        user_id = None
        if len(parts) == 2 and parts[0].lower() == "bearer":
            try:
                user_id = await run_in_threadpool(_resolve_user_id, parts[1], base)
            except SQLAlchemyError:
                await JSONResponse({"error": "server_error"}, status_code=503)(scope, receive, send)
                return
        if user_id is None:
            await JSONResponse({"error": "invalid_token"}, status_code=401, headers={
                "WWW-Authenticate": (
                    f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource", '
                    f'scope="{SCOPE_READ} {SCOPE_WRITE}"'
                ),
            })(scope, receive, send)
            return

        context_token = authenticated_user_id.set(user_id)
        try:
            await scope["app"].state.mcp_app(scope, receive, send)
        finally:
            authenticated_user_id.reset(context_token)
