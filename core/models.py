"""Modelo de datos (SQLAlchemy 2.0). SQLite para el MVP, PostgreSQL por URL."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Base(DeclarativeBase):
    pass


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("smp"))
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    md5: Mapped[str] = mapped_column(String(32), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    filename: Mapped[str] = mapped_column(String(255), default="")
    extension: Mapped[str] = mapped_column(String(16), default="")
    detected_type: Mapped[str] = mapped_column(String(32), default="unknown")
    mime: Mapped[str] = mapped_column(String(120), default="")
    storage_key: Mapped[str] = mapped_column(String(120), default="")
    parent_id: Mapped[str | None] = mapped_column(String(40), ForeignKey("samples.id"), nullable=True)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(24), default="received")
    meta: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    children: Mapped[list[Sample]] = relationship(
        "Sample", backref="parent", remote_side=[id], lazy="selectin"
    )


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("inv"))
    sample_id: Mapped[str] = mapped_column(String(40), ForeignKey("samples.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="queued")
    verdict: Mapped[str] = mapped_column(String(24), default="pending")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    llm_status: Mapped[str] = mapped_column(String(24), default="disabled")
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    report_json: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    sample: Mapped[Sample] = relationship(lazy="joined")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("ev"))
    investigation_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("investigations.id"), index=True
    )
    sample_id: Mapped[str] = mapped_column(String(40), default="")
    tool: Mapped[str] = mapped_column(String(48), default="")
    category: Mapped[str] = mapped_column(String(48), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    raw_ref: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("run"))
    investigation_id: Mapped[str] = mapped_column(String(40), index=True)
    tool_id: Mapped[str] = mapped_column(String(48))
    tool_version: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(24), default="ok")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    warnings: Mapped[str] = mapped_column(Text, default="[]")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("art"))
    sample_id: Mapped[str] = mapped_column(String(40), index=True)
    kind: Mapped[str] = mapped_column(String(32), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    storage_key: Mapped[str] = mapped_column(String(120), default="")
    child_sample_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("ioc"))
    type: Mapped[str] = mapped_column(String(24), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    defanged: Mapped[str] = mapped_column(String(512), default="")
    verdict: Mapped[str] = mapped_column(String(24), default="unknown")
    source: Mapped[str] = mapped_column(String(48), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IOCOccurrence(Base):
    __tablename__ = "ioc_occurrences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_id: Mapped[str] = mapped_column(String(40), ForeignKey("iocs.id"), index=True)
    evidence_id: Mapped[str] = mapped_column(String(40), index=True)
    investigation_id: Mapped[str] = mapped_column(String(40), default="")
