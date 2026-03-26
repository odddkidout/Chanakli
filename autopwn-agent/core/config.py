"""Application settings loaded from environment / .env file."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Target
    target_host: str = "pigi.in"
    target_url: str = "https://pigi.in"

    # LLM
    litellm_base_url: str = "http://localhost:4000"
    auditor_model: str = "openai/gpt-4o"
    executor_model: str = "openai/gpt-4o-mini"
    openai_api_key: str = ""

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    session_ttl: int = 86400

    # Postgres
    database_url: str = "postgresql://autopwn:autopwn@localhost:5432/autopwn"

    # ChromaDB
    chromadb_host: str = "localhost"
    chromadb_port: int = 8000

    # Agent tuning
    max_iterations: int = 10
    confidence_threshold: float = 0.7
    reproducibility_runs: int = 3
    request_timeout: int = 30

    # Safety
    dry_run: bool = False
    safe_mode: bool = True
