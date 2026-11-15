#!/usr/bin/env python
"""Matriz de herramientas y estado del sandbox (sin analizar muestras)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from core.settings import get_settings  # noqa: E402
from tools import registry  # noqa: E402
from tools.bootstrap import register_all  # noqa: E402
from tools.executors.docker_exec import docker_status  # noqa: E402


def main() -> int:
    register_all()
    settings = get_settings()
    status = docker_status()

    print(f"EXECUTOR={settings.executor} · docker={'sí' if status['docker_available'] else 'no'}")
    for image, ok in status["images"].items():
        print(f"  {'OK ' if ok else '-- '} {image}")
    print()

    items = registry.list_tools()
    width = max(len(i["id"]) for i in items) + 2
    print(f"{'HERRAMIENTA':<{width}} {'VERSIÓN':<8} {'SANDBOX':<7} {'ESTADO':<14} IMAGEN")
    print("-" * 100)
    for item in items:
        image = item["docker_image"] or "-"
        ok, reason = registry.availability(item["id"])
        state = "disponible" if ok else "no disponible"
        print(f"{item['id']:<{width}} {item['version']:<8} "
              f"{('sí' if item['docker_image'] else 'no'):<7} {state:<14} {image}")
        if not ok:
            print(f"{'':<{width}} motivo: {reason}")
    print()
    print(f"{len(items)} herramientas · {sum(1 for i in items if i['docker_image'])} con imagen de sandbox")
    print(f"Aislamiento: red={status['isolation']['network']}, rootfs RO, "
          f"cap_drop={status['isolation']['cap_drop']}, mem={status['isolation']['memory_mb']}MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
