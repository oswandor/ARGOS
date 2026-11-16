"""Registro central de herramientas.

Toda ejecución pasa por aquí: allowlist -> disponibilidad -> presupuesto ->
ejecución -> resultado normalizado. El agente nunca invoca un adaptador directo.
"""

from __future__ import annotations

import importlib.util
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from core.policy import Budget, PolicyError, authorize
from core.settings import get_settings
from tools.base import DockerTool, ToolContext, ToolOutput
from tools.executors import docker_exec, runner_exec


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    version: str
    formats: tuple[str, ...]
    description: str
    safety: str = "static"  # static | emulation | dynamic
    requires: tuple[str, ...] = ()
    timeout_s: float = 60.0
    docker: DockerTool | None = None


@dataclass
class Registered:
    spec: ToolSpec
    fn: Callable[[ToolContext], ToolOutput]
    notes: list[str] = field(default_factory=list)


_REGISTRY: dict[str, Registered] = {}


def register(spec: ToolSpec, fn: Callable[[ToolContext], ToolOutput], notes: list[str] | None = None) -> None:
    _REGISTRY[spec.id] = Registered(spec=spec, fn=fn, notes=notes or [])


def get(tool_id: str) -> Registered:
    if tool_id not in _REGISTRY:
        raise KeyError(f"herramienta no registrada: {tool_id}")
    return _REGISTRY[tool_id]


def unregister(tool_id: str) -> None:
    """Elimina una herramienta del registro (tests y recarga de configuración)."""
    _REGISTRY.pop(tool_id, None)


def availability(tool_id: str) -> tuple[bool, str]:
    reg = get(tool_id)
    missing = [m for m in reg.spec.requires if importlib.util.find_spec(m) is None]
    if missing:
        return False, f"faltan dependencias: {', '.join(missing)}"
    return True, ""


def list_tools() -> list[dict]:
    out = []
    for tool_id in sorted(_REGISTRY):
        reg = _REGISTRY[tool_id]
        ok, reason = availability(tool_id)
        out.append(
            {
                "id": tool_id,
                "name": reg.spec.name,
                "version": reg.spec.version,
                "formats": list(reg.spec.formats),
                "safety": reg.spec.safety,
                "description": reg.spec.description,
                "available": ok,
                "unavailable_reason": reason,
                "docker_image": reg.spec.docker.image if reg.spec.docker else None,
                "notes": reg.notes,
            }
        )
    return out


def _executor_mode() -> str:
    return get_settings().executor.strip().lower()


def _docker_ready(spec: ToolSpec) -> tuple[bool, str]:
    if spec.docker is None:
        return False, "herramienta sin imagen de sandbox"
    if not docker_exec.docker_available():
        return False, "daemon de Docker no disponible"
    if not docker_exec.image_available(spec.docker.image):
        return False, f"imagen no construida: {spec.docker.image}"
    return True, ""


def _runner_ready(spec: ToolSpec) -> tuple[bool, str]:
    if spec.docker is None:
        return False, "herramienta sin imagen de sandbox"
    status = runner_exec.runner_status()
    if not status.get("available"):
        return False, status.get("reason", "sandbox-runner no disponible")
    if not status.get("images", {}).get(spec.docker.image, False):
        return False, f"imagen no construida: {spec.docker.image}"
    return True, ""


def run(
    tool_id: str,
    ctx: ToolContext,
    budget: Budget,
    *,
    is_child: bool = False,
) -> ToolOutput:
    """Ejecuta una herramienta autorizada. Nunca lanza por fallo de la herramienta."""
    reg = get(tool_id)
    authorize(tool_id, ctx.detected_type, is_child=is_child)

    # En modo runner las dependencias viven en las imágenes, no en la API.
    mode = _executor_mode()
    ok, reason = availability(tool_id)
    if mode == "runner" and reg.spec.docker is not None:
        ok, reason = True, ""
    if not ok:
        return ToolOutput(
            status="unavailable",
            warnings=[f"{reg.spec.name} no disponible: {reason}"],
            tool_id=tool_id,
            tool_version=reg.spec.version,
        )

    budget.check_time()
    budget.spend_tool_call(tool_id)

    fallback_note = ""
    if mode == "runner" and reg.spec.docker is not None:
        ready, why = _runner_ready(reg.spec)
        if not ready:
            return ToolOutput(
                status="unavailable",
                warnings=[f"sandbox-runner no disponible para {tool_id}: {why}"],
                tool_id=tool_id,
                tool_version=reg.spec.version,
            )
        started = time.perf_counter()
        try:
            out = runner_exec.run_in_runner(
                image=reg.spec.docker.image,
                tool=reg.spec.docker.tool,
                ctx=ctx,
                timeout_s=reg.spec.docker.timeout_s or reg.spec.timeout_s,
            )
        except runner_exec.RunnerUnavailable as exc:
            out = ToolOutput(status="unavailable", warnings=[str(exc)])
        except Exception as exc:  # noqa: BLE001
            out = ToolOutput(status="error", warnings=[f"fallo del sandbox-runner: {type(exc).__name__}: {exc}"])
        out.tool_id = tool_id
        out.tool_version = out.tool_version or reg.spec.version
        out.duration_ms = int((time.perf_counter() - started) * 1000)
        out.sandbox = True
        return out
    if mode in {"docker", "auto"} and reg.spec.docker is not None:
        ready, why = _docker_ready(reg.spec)
        if ready:
            started = time.perf_counter()
            try:
                out = docker_exec.run_in_docker(
                    image=reg.spec.docker.image,
                    tool=reg.spec.docker.tool,
                    ctx=ctx,
                    timeout_s=reg.spec.docker.timeout_s or reg.spec.timeout_s,
                )
            except docker_exec.DockerUnavailable as exc:
                out = ToolOutput(status="unavailable", warnings=[str(exc)])
            except Exception as exc:  # noqa: BLE001 - el sandbox falla, el análisis no
                out = ToolOutput(
                    status="error",
                    warnings=[f"fallo del sandbox {reg.spec.docker.image}: {type(exc).__name__}: {exc}"],
                )
            out.tool_id = tool_id
            out.tool_version = out.tool_version or reg.spec.version
            out.duration_ms = int((time.perf_counter() - started) * 1000)
            out.sandbox = True
            return out

        if mode == "docker":
            return ToolOutput(
                status="unavailable",
                warnings=[f"sandbox no disponible para {tool_id}: {why}"],
                tool_id=tool_id,
                tool_version=reg.spec.version,
            )
        # mode == auto: se degrada a in-process dejando constancia explícita
        fallback_note = f"{tool_id}: ejecución in-process ({why})"

    started = time.perf_counter()
    try:
        out = reg.fn(ctx)
        if not isinstance(out, ToolOutput):
            raise TypeError(f"{tool_id} devolvió {type(out).__name__}, se esperaba ToolOutput")
    except PolicyError:
        raise
    except Exception as exc:  # noqa: BLE001 - se degrada, no se propaga
        out = ToolOutput(
            status="error",
            warnings=[f"fallo en {tool_id}: {type(exc).__name__}: {exc}"],
        )
    out.tool_id = tool_id
    out.tool_version = reg.spec.version
    out.duration_ms = int((time.perf_counter() - started) * 1000)
    if fallback_note:
        out.warnings.append(fallback_note)
    return out
