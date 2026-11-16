"""Sesión y creación de esquema."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.models import Base
from core.settings import get_settings

_settings = get_settings()
_settings.data_dir.mkdir(parents=True, exist_ok=True)

_connect_args = {"check_same_thread": False} if _settings.db_url.startswith("sqlite") else {}
engine = create_engine(_settings.db_url, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
