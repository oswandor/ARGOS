"""Almacenamiento inmutable de muestras y artefactos.

LocalStorage es el backend del MVP (sin Docker). La interfaz es deliberadamente
mínima para poder sustituirla por MinIO/S3 sin tocar el pipeline.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Protocol


class Storage(Protocol):
    def put(self, key: str, data: bytes) -> str: ...
    def get(self, key: str) -> bytes: ...
    def exists(self, key: str) -> bool: ...
    def path(self, key: str) -> Path | None: ...


def _safe_key(key: str) -> str:
    key = key.replace("\\", "/").lstrip("/")
    if ".." in key.split("/"):
        raise ValueError(f"clave de almacenamiento inválida: {key!r}")
    return key


class LocalStorage:
    """Escribe en ``data/blobs`` con nombres derivados del hash (inmutables)."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        key = _safe_key(key)
        target = (self.root / key).resolve()
        if not str(target).startswith(str(self.root.resolve())):
            raise ValueError("ruta fuera del almacenamiento")
        return target

    def put(self, key: str, data: bytes) -> str:
        target = self._resolve(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            return key  # inmutable: nunca se sobrescribe
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)
        return key

    def get(self, key: str) -> bytes:
        return self._resolve(key).read_bytes()

    def exists(self, key: str) -> bool:
        return self._resolve(key).is_file()

    def path(self, key: str) -> Path:
        return self._resolve(key)


def sample_key(sha256: str) -> str:
    return f"samples/{sha256[:2]}/{sha256[2:4]}/{sha256}"


def artifact_key(sha256: str, kind: str) -> str:
    safe_kind = "".join(c for c in kind if c.isalnum() or c in "-_")[:24] or "blob"
    return f"artifacts/{sha256[:2]}/{sha256[2:4]}/{sha256}.{safe_kind}"


def key_for_bytes(data: bytes, prefix: str = "artifacts") -> tuple[str, str]:
    digest = hashlib.sha256(data).hexdigest()
    return digest, f"{prefix}/{digest[:2]}/{digest[2:4]}/{digest}"
