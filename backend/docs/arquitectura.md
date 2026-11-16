# ARGOS — Arquitectura actual

Documento vivo del sistema tal como está desplegado hoy (v0.2.0). El diseño histórico con MCP
quedó descartado; la orquestación multiagente es **CrewAI** y las herramientas se ejecutan en
**workers Docker** a través de un **sandbox-runner** interno.

## 1. Principios

1. **La IA decide poco y ejecuta nada.** El LLM solo puede pedir herramientas del registro y
   redactar; el backend valida allowlist, presupuesto y tipo.
2. **Veredicto determinista.** Riesgo y veredicto salen de `core/scoring.py`; el LLM ajusta como
   máximo ±0.05 de confianza.
3. **Zonas separadas.** API (sin Docker), runner (con Docker), workers (sin red ni root).
4. **Evidencia primero.** Cada hallazgo tiene `evidence_id`; el informe declara cobertura y
   limitaciones, y puede decir `inconclusive`.
5. **Degradación obligatoria.** Sin DeepSeek, sin crew o con un worker caído, el análisis termina.

## 2. Topología

```
host (Docker Desktop / WSL2)
│
├── api            FastAPI + pipeline + CrewAI + informes
│   ├── postgres    metadatos, evidencia, IOCs
│   ├── /data       volumen argos_data: muestras y artefactos
│   ├── ./reports   bind mount: informes JSON/MD/HTML
│   └── HTTPS ────► api.deepseek.com (solo evidencia sanitizada)
│
├── sandbox-runner  único con /var/run/docker.sock
│   └── crea/elimina workers efímeros
│
└── workers (5 imágenes)
    pdf · office · js · binary · yara
    network=none · read-only · cap_drop=ALL · uid 10001 · límites
```

Puertos: `127.0.0.1:8000` (API, configurable con `ARGOS_API_PORT`). PostgreSQL y el runner no se
publican; solo son accesibles en la red interna de Compose.

## 3. Componentes

| Componente | Responsabilidad | No hace |
| --- | --- | --- |
| `api/` | HTTP, ingesta, orquestación, informes | No crea contenedores |
| `core/` | settings, DB, storage, sanitizer, policy, scoring, LLM, report | No ejecuta herramientas |
| `agents/` | CrewAI: supervisor, especialistas, validador, redactor | No ejecuta binarios |
| `graphs/pipeline.py` | fases, presupuesto, evidencia, fallback | No habla con Docker |
| `tools/registry.py` | allowlist, disponibilidad, dispatch, versiones | No interpreta contenido |
| `tools/executors/` | `runner_exec` (Compose), `docker_exec` (host), in-process | No autoriza |
| `workers/` | entrypoint del contenedor, enriquecimiento con motores reales | No habla con la API |
| `runner/` | valida y lanza workers; sonda `/ready`, `/health`, `/v1/run` | No analiza muestras |
| `postgres` | persistencia relacional | — |

## 4. Flujo de una investigación

1. `POST /malware-samples` → límite de tamaño, SHA-256, tipo real, dedupe, cuarentena en `/data/blobs`.
2. Se crea `investigation` y se ejecuta el pipeline (síncrono con `wait=true`, en segundo plano
   con `wait=false`).
3. **CrewAI fase 1**: el supervisor consulta capacidades y ejecuta herramientas con
   `run_analysis`. Cada llamada pasa por `registry.run` → `runner_exec` → `sandbox-runner` →
   `docker create/start` del worker.
4. Si el supervisor no ejecutó herramientas de contenido, el backend aplica el **plan
   determinista de respaldo** (`pdfid`/`pdf_parser`/`office_scan`/`js_analyzer`/`shellcode` + yara).
5. Los artefactos (JS, DOCM, macros, archivos de emulación) se registran como muestras hijas y se
   analizan recursivamente hasta `MAX_DEPTH`.
6. Reputación local de IOCs (siempre en el backend, nunca en el LLM).
7. **CrewAI fase 2**: especialistas por familia → validador → redactor. Los resultados se validan
   contra Pydantic; si fallan, se descartan.
8. `core/scoring.py` agrega la evidencia (máximo por categoría, sin doble conteo), calcula
   veredicto/riesgo/ATT&CK y aplica el ajuste de confianza acotado.
9. Se genera el informe (`argos.report/1`) y se guarda en Postgres y en `reports/out/`.

## 5. Registro de herramientas y ejecutores

`ToolSpec` declara: `id`, versión, formatos, descripción, `requires`, timeout e imagen Docker.
`registry.run()` hace, en orden: allowlist por tipo → disponibilidad → presupuesto → ejecución →
normalización a `ToolOutput` (hallazgos, artefactos, motores, sandbox, duración).

| Modo (`EXECUTOR`) | Cuándo | Cómo |
| --- | --- | --- |
| `runner` | **Compose (producción local)** | HTTP interno al sandbox-runner con token |
| `docker` | API en host con Docker CLI | `docker run` endurecido desde el host |
| `auto` | Desarrollo | Docker si hay daemon; si no, in-process + warning |
| `inprocess` | Tests | Adaptadores nativos en el proceso |

En Compose, `EXECUTOR=runner`. La API no ve el daemon de Docker.

## 6. Contrato worker ↔ runner

El runner monta la muestra en un volumen efímero (`/work:ro`), prepara `/out:rw`, crea el
contenedor con la política fija y espera. El worker escribe `/out/result.json`:

```json
{
  "status": "ok",
  "findings": [{"category": "macro", "description": "...", "suspicious": true, "score": 3.5}],
  "artifacts": [{"kind": "vba", "filename": "Module1", "path": "artifact_0000_vba.bin", "size": 512}],
  "data": {"olevba": {"count": 1}},
  "warnings": [],
  "metrics": {"vba_bytes": 512},
  "engines": {"oletools": "0.60.2"},
  "engine_version": "1.1"
}
```

Reglas: stdout no es canal de resultados; los artefactos se referencian por nombre plano; el
runner limita tamaño de petición, resultado y artefactos; un timeout elimina el contenedor.

## 7. Modelo de datos (resumen)

- `samples`: hash, tipo, tamaño, `parent_id`, `depth`, clave de almacenamiento.
- `investigations`: estado, veredicto, confianza, riesgo, tokens, informe JSON.
- `evidence`: hallazgo con herramienta, categoría, objeto, score y `evidence_id`.
- `tool_runs`: auditoría de ejecución (estado, duración, versión).
- `artifacts`: artefactos y su muestra hija.
- `iocs` / `ioc_occurrences`: correlación local.

## 8. Decisiones de diseño

| Decisión | Motivo |
| --- | --- |
| CrewAI en vez de LangGraph | El plan lo permitía y encaja con agentes por rol; se conserva el pipeline determinista como respaldo |
| `deepseek-chat` para el crew | Sin *thinking*: respuestas estables y ~1.5 s por llamada; `flash` devolvía contenido vacío en prompts largos |
| `sandbox-runner` con el socket | La API no puede crear contenedores; el runner valida imagen/herramienta y aplica la política |
| PostgreSQL en Compose | Persistencia real y auditoría; el modo host puede seguir con SQLite |
| Sin Celery todavía | `BackgroundTasks` basta para un solo nodo; la interfaz de ejecución ya es sustituible |
| Informes en bind mount | Visibles desde Windows sin `docker cp` |

## 9. Límites conocidos

- Docker comparte kernel: barrera de parsing, no de detonación.
- La cadena de ataque es observada (estático/emulación) e inferida; no hay ejecución real.
- Sin cola distribuida ni MinIO; un solo nodo.
- `box-js` puede fallar en scripts complejos y se marca `partial`.
- El plan del supervisor se redacta antes de los hijos; el validador lo corrige y la evidencia manda.
