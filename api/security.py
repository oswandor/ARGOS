"""Autenticación mínima del MVP (API key opcional)."""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from core.settings import get_settings


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected = get_settings().api_key.strip()
    if not expected:
        return  # desarrollo local sin autenticación
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key inválida o ausente",
        )
