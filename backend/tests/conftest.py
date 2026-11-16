"""Configuración de tests: BD y almacenamiento aislados por sesión."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TMP = Path(tempfile.mkdtemp(prefix="argos-test-"))
os.environ["DATA_DIR"] = str(TMP)
os.environ["DATABASE_URL"] = f"sqlite:///{(TMP / 'test.db').as_posix()}"
os.environ["ENABLE_LLM"] = "false"
os.environ["API_KEY"] = ""
os.environ["MAX_UPLOAD_MB"] = "10"
os.environ["EXECUTOR"] = "inprocess"  # los tests no dependen del daemon de Docker

import pytest  # noqa: E402

from core.db import SessionLocal, engine, init_db  # noqa: E402
from core.models import Base  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _database() -> None:
    init_db()


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture()
def clean_db():
    """BD vacía para tests que necesitan conteos exactos."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
