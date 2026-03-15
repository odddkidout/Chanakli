from __future__ import annotations

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # LiteLLM
    litellm_base_url: str = Field("http://localhost:4000", env="LITELLM_BASE_URL")
    auditor_model: str = Field("glm-5", env="AUDITOR_MODEL")
    executor_model: str = Field("mimo-v2-flash", env="EXECUTOR_MODEL")

    # Storage
    redis_url: str = Field("redis://localhost:6379", env="REDIS_URL")
    postgres_url: str = Field(
        "postgresql://autopwn:autopwn@localhost:5432/autopwn", env="POSTGRES_URL"
    )
    chroma_path: str = Field("./data/chroma", env="CHROMA_PATH")

    # Optional API keys for recon
    shodan_api_key: Optional[str] = Field(None, env="SHODAN_API_KEY")
    censys_api_key: Optional[str] = Field(None, env="CENSYS_API_KEY")

    # Safety
    max_iterations: int = Field(50, env="MAX_ITERATIONS")
    tool_timeout: int = Field(60, env="TOOL_TIMEOUT")
    require_scope_confirmation: bool = Field(True, env="REQUIRE_SCOPE_CONFIRMATION")

    # Verification
    verification_confidence_threshold: float = Field(0.7, env="VERIFICATION_CONFIDENCE_THRESHOLD")
    verification_reproducibility_runs: int = Field(3, env="VERIFICATION_REPRODUCIBILITY_RUNS")
    verification_required_successes: int = Field(2, env="VERIFICATION_REQUIRED_SUCCESSES")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
