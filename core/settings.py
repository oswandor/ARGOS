"""ARGOS — configuración central.

Todas las decisiones operativas (modelo, límites, privacidad) viven aquí y se
pueden sobrescribir por entorno. El código nunca lee ``os.environ`` directamente.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- DeepSeek ---
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    model_fast: str = "deepseek-flash"
    model_deep: str = "deepseek-v4-pro"
    enable_llm: bool = True
    llm_timeout_s: float = 90.0
    max_tokens_per_investigation: int = 60_000
    # Si es True, al LLM solo viajan hechos; nunca fragmentos de código.
    strict_privacy: bool = True

    # --- Orquestación multiagente (CrewAI) ---
    crew_enabled: bool = True
    # deepseek-chat = alias sin thinking: más rápido y sin respuestas vacías.
    crew_model: str = "deepseek-chat"
    crew_max_tool_calls: int = 4
    # Salida detallada de CrewAI (rol, tarea, Thinking..., Final Answer) en los logs.
    crew_verbose: bool = True

    # --- Ejecución de herramientas ---
    # auto: Docker si hay daemon e imagen; si no, in-process.
    # docker: exige sandbox (si falta, la herramienta se reporta no disponible).
    # inprocess: solo para tests/desarrollo.
    executor: str = "auto"
    docker_binary: str = "docker"
    worker_image_prefix: str = "argos/worker"
    worker_image_tag: str = "0.1.0"
    docker_memory_mb: int = 768
    docker_cpus: float = 1.0
    docker_timeout_s: float = 120.0
    sandbox_runner_url: str = ""
    runner_shared_token: str = ""

    # --- API ---
    api_key: str = ""  # vacío = sin autenticación (solo desarrollo local)
    max_upload_mb: int = 50

    # --- Límites de análisis ---
    max_depth: int = 3
    max_children: int = 20
    max_artifact_bytes: int = 5 * 1024 * 1024
    max_js_bytes: int = 200_000
    max_streams: int = 400

    # --- Almacenamiento ---
    data_dir: Path = BASE_DIR / "data"
    database_url: str = ""  # vacío => sqlite en data/argos.db

    # --- Terceros ---
    allow_external_intel: bool = False
    virus_total_api_key: str = ""

    log_level: str = "INFO"

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite:///{(self.data_dir / 'argos.db').as_posix()}"

    @property
    def blob_dir(self) -> Path:
        return self.data_dir / "blobs"

    @property
    def llm_enabled(self) -> bool:
        return bool(self.enable_llm and self.deepseek_api_key.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
