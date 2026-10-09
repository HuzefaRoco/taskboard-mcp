from urllib.parse import urlsplit

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.web import router

settings = get_settings()
app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=urlsplit(settings.public_base_url).scheme == "https",
)
app.include_router(router)
