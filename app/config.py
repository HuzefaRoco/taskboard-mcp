from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    public_base_url: str
    session_secret: str
    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 2592000

    @field_validator("public_base_url")
    @classmethod
    def strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings(_env_file=".env")
