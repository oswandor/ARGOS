# ARGOS — Backlog por fases

> **Documento histórico de planificación.** Algunas historias mencionan MCP, Celery o MinIO y no
> reflejan la implementación actual (CrewAI + sandbox-runner + PostgreSQL). El estado real está en
> [README.md](../README.md) y [docs/mvp.md](mvp.md).

Estimaciones en puntos de historia (1 pt ≈ media jornada de 4 h). Un solo desarrollador.

## Épica 0 — Fundaciones (5 pts)

| ID | Historia | Pts | Criterio de done |
| --- | --- | --- | --- |
| F0-1 | Repo, `pyproject.toml`, ruff, pytest, pre-commit | 1 | `make lint test` verde |
| F0-2 | `docker-compose.dev.yml`: Postgres, Redis, MinIO | 1 | healthchecks OK |
| F0-3 | `core/settings.py` con Pydantic Settings y `.env` | 1 | test de carga y validación |
| F0-4 | `core/llm.py` + `scripts/ping_deepseek.py` (tool call + JSON validado) | 2 | llamada real OK, costo logueado |

## Épica 1 — Ingesta y clasificación (13 pts)

| ID | Historia | Pts | Depende |
| --- | --- | --- | --- |
| F1-1 | `POST /samples` con límite de tamaño y hash | 2 | F0 |
| F1-2 | Detección de tipo real (magic + libmagic) y rechazo | 2 | F1-1 |
| F1-3 | Cuarentena en MinIO con clave por SHA-256 | 2 | F1-1 |
| F1-4 | Deduplicación por hash | 1 | F1-3 |
| F1-5 | Worker YARA + 20 reglas base | 2 | F0-2 |
| F1-6 | Worker PDFiD | 2 | F1-3 |
| F1-7 | Modelo de datos + migraciones Alembic | 2 | F0-2 |

## Épica 2 — PDF y Office (21 pts)

| ID | Historia | Pts | Depende |
| --- | --- | --- | --- |
| F2-1 | MCP `pdf-tools-mcp` con `scan_pdf` | 3 | F1-6 |
| F2-2 | `inspect_pdf_object` + `extract_pdf_streams` | 3 | F2-1 |
| F2-3 | `list_embedded_files` + creación de sample hijo | 2 | F2-2 |
| F2-4 | MCP `office-tools-mcp`: `extract_vba`, `detect_autoexec` | 3 | F1-3 |
| F2-5 | `inspect_ole` + objetos embebidos | 2 | F2-4 |
| F2-6 | Agente PDF (prompt + nodo) | 3 | F2-2, F0-4 |
| F2-7 | Agente Office (prompt + nodo) | 3 | F2-5, F0-4 |
| F2-8 | Esquemas Pydantic de evidencia + validación | 2 | F2-1 |

## Épica 3 — JavaScript y shellcode (18 pts)

| ID | Historia | Pts | Depende |
| --- | --- | --- | --- |
| F3-1 | Worker box-js aislado (sin red, timeouts) | 3 | F0-2 |
| F3-2 | MCP `javascript-mcp`: `parse_js_ast`, `deobfuscate_js` | 3 | F3-1 |
| F3-3 | `analyze_js` + normalización de traza a JSON | 3 | F3-1 |
| F3-4 | Extractor de IOCs JS con defanging | 2 | F3-3 |
| F3-5 | MCP `binary-mcp`: arquitectura + Capstone | 3 | F1-3 |
| F3-6 | `extract_strings` + mapa de entropía | 2 | F3-5 |
| F3-7 | Tests adversariales (JS infinito, PDF recursivo) | 2 | F3-1 |

## Épica 4 — Orquestación (21 pts)

| ID | Historia | Pts | Depende |
| --- | --- | --- | --- |
| F4-1 | Grafo base con estado tipado y checkpointer | 3 | F2-6, F2-7 |
| F4-2 | Nodo `route` con salida JSON validada | 2 | F4-1 |
| F4-3 | `policy_engine` (allowlist, límites, presupuesto) | 3 | F4-1 |
| F4-4 | Integración MCP ↔ LangGraph (`langchain-mcp-adapters`) | 3 | F4-1 |
| F4-5 | Nodos especialistas conectados al grafo | 3 | F4-2, F3-2 |
| F4-6 | Interrupciones y aprobación humana | 2 | F4-1 |
| F4-7 | Reanudación tras fallo + tests | 3 | F4-1 |
| F4-8 | Presupuesto por investigación y corte limpio | 2 | F4-3 |

## Épica 5 — Inteligencia y reportes (18 pts)

| ID | Historia | Pts | Depende |
| --- | --- | --- | --- |
| F5-1 | MCP `threat-intel-mcp` con caché y rate limit | 3 | F0-4 |
| F5-2 | Modo offline (MISP/local) | 2 | F5-1 |
| F5-3 | Motor de correlación (IOC compartidos, TLSH) | 3 | F1-7 |
| F5-4 | Plantilla de informe Jinja2 → PDF | 3 | F4-5 |
| F5-5 | JSON estable + `report.schema.json` | 2 | F5-4 |
| F5-6 | Mapeo ATT&CK curado | 2 | F5-4 |
| F5-7 | Memoria de investigaciones (búsqueda por IOC) | 3 | F5-3 |

## Épica 6 — Detonación (opcional, 21 pts)

| ID | Historia | Pts |
| --- | --- | --- |
| F6-1 | `vm_controller` con aprobación obligatoria | 3 |
| F6-2 | VM Windows + snapshot + reversión verificada | 5 |
| F6-3 | Red simulada (INetSim) + deny-all | 3 |
| F6-4 | Integración CAPE + normalización de comportamiento | 5 |
| F6-5 | Correlación estático ↔ dinámico | 3 |
| F6-6 | Pruebas de contención (la VM no alcanza el host) | 2 |

## Épica 7 — Operación (18 pts)

| ID | Historia | Pts |
| --- | --- | --- |
| F7-1 | Dashboard React: lista y detalle | 5 |
| F7-2 | Métricas Prometheus + dashboards Grafana | 3 |
| F7-3 | Auditoría de aprobaciones y accesos | 3 |
| F7-4 | Backups y retención | 3 |
| F7-5 | RBAC y SSO | 4 |

## Total

| Épicas | Pts |
| --- | --- |
| 0–5 (v1) | 96 |
| 6–7 (extendido) | 39 |
| **Total** | **135** |

A 10–12 h/semana, v1 (96 pts ≈ 48 jornadas) ocupa **16 semanas**; el plan de 24 semanas incluye
margen para imprevistos y las fases 6–7.
