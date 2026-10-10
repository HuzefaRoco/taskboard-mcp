from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.sessions import SessionMiddleware
from starlette.routing import Route

from app import oauth
from app.config import get_settings
from app.mcp_server import AuthenticatedMCP, authenticated_user_id, build_mcp_server
from app.web import router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    base = urlsplit(get_settings().public_base_url)
    server = build_mcp_server(authenticated_user_id.get)
    mcp_app = server.streamable_http_app(
        streamable_http_path="/mcp", json_response=True, stateless_http=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[base.netloc], allowed_origins=[f"{base.scheme}://{base.netloc}"],
        ),
    )
    app.state.mcp_app = mcp_app
    async with mcp_app.router.lifespan_context(mcp_app):
        yield


settings = get_settings()
app = FastAPI(lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=urlsplit(settings.public_base_url).scheme == "https",
)
app.include_router(router)
app.include_router(oauth.router)
# Route accepts the exact /mcp path without Mount's trailing-slash redirect.
app.router.routes.append(Route("/mcp", endpoint=AuthenticatedMCP()))
