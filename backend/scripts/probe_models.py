#!/usr/bin/env python
"""Diagnóstico de modelos DeepSeek: lista modelos y prueba JSON mode/thinking.

Uso: python scripts/probe_models.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from openai import OpenAI  # noqa: E402

from core.settings import get_settings  # noqa: E402


def main() -> int:
    settings = get_settings()
    if not settings.deepseek_api_key:
        print("Falta DEEPSEEK_API_KEY en .env")
        return 2

    client = OpenAI(
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        timeout=60,
        max_retries=0,
    )

    print("Modelos visibles para esta clave:")
    try:
        for model in client.models.list().data:
            print("  -", model.id)
    except Exception as exc:  # noqa: BLE001
        print("  (no se pudo listar:", type(exc).__name__, exc, ")")

    prompt = "Responde con un objeto JSON con las claves verdict (string) y confidence (número)."
    for model in ("deepseek-flash", "deepseek-chat", "deepseek-v4-pro"):
        started = time.perf_counter()
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.0,
                max_tokens=1200,
            )
            elapsed = int((time.perf_counter() - started) * 1000)
            choice = response.choices[0]
            content = choice.message.content or ""
            reasoning = getattr(choice.message, "reasoning_content", None) or ""
            usage = response.usage
            print(
                f"\n{model}: finish={choice.finish_reason} {elapsed}ms "
                f"tokens={usage.total_tokens if usage else '?'} "
                f"content={len(content)} reasoning={len(reasoning)}"
            )
            print("  content:", content[:200].replace("\n", " "))
        except Exception as exc:  # noqa: BLE001
            elapsed = int((time.perf_counter() - started) * 1000)
            print(f"\n{model}: ERROR {type(exc).__name__} {elapsed}ms -> {str(exc)[:250]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
