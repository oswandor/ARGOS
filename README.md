# ARGOS

**Laboratorio de análisis de malware documental con agentes de IA y sandbox Docker**

> Argos Panoptes: muchos ojos sobre una misma muestra.

ARGOS recibe un archivo sospechoso (PDF, Office, JavaScript o shellcode), lo analiza
**estáticamente** dentro de contenedores aislados, correlaciona la evidencia, calcula un
veredicto con nivel de confianza y genera un informe **JSON / Markdown / HTML** que explica
qué se observó, qué se infirió y qué **no** se pudo comprobar.

La pila completa (API + PostgreSQL + sandbox-runner + 5 workers + agentes CrewAI) se levanta
con un solo comando y no necesita Python instalado en el host.

---

## Índice

1. [Qué hace y qué no](#1-qué-hace-y-qué-no)
2. [Arquitectura](#2-arquitectura)
3. [Requisitos](#3-requisitos)
4. [Puesta en marcha](#4-puesta-en-marcha)
5. [Uso](#5-uso)
6. [Cómo funciona el análisis](#6-cómo-funciona-el-análisis)
7. [Agentes CrewAI](#7-agentes-crewai)
8. [Sandbox y aislamiento](#8-sandbox-y-aislamiento)
9. [Configuración](#9-configuración)
10. [API REST](#10-api-rest)
11. [Datos y persistencia](#11-datos-y-persistencia)
12. [Operación diaria](#12-operación-diaria)
13. [Tests y calidad](#13-tests-y-calidad)
14. [Estructura del repositorio](#14-estructura-del-repositorio)
15. [Seguridad y límites](#15-seguridad-y-límites)
16. [Estado y roadmap](#16-estado-y-roadmap)
17. [Solución de problemas](#17-solución-de-problemas)
18. [Documentación](#18-documentación)

---

## 1. Qué hace y qué no

**Hace**

- Ingesta con SHA-256, deduplicación y cuarentena inmutable en un volumen Docker.
- Triage por firma real (no por extensión), entropía y coherencia de nombre.
- PDF: PDFiD y pdf-parser (Didier Stevens) + parser propio; objetos, streams FlateDecode,
  `/OpenAction`, `/JS`, archivos embebidos.
- Office: oletools (olevba/oleobj/mraptor) sobre OOXML y OLE.
- JavaScript: análisis estático + emulación con box-js (IOCs, `IOC.json`, archivos generados).
- Shellcode/binario: arquitectura, Capstone, LIEF, objdump.
- YARA con reglas propias y correlación local de IOCs.
- Análisis recursivo padre-hijo con límites de profundidad, tamaño y presupuesto.
- 6 agentes CrewAI (supervisor, especialistas, validador, redactor) sobre DeepSeek.
- Informe con `evidence_id` por hallazgo, IOCs *defanged*, MITRE ATT&CK, cadena de ataque,
  cobertura real, limitaciones y recomendaciones.
- API REST con Swagger, informes descargables y estado del sandbox.

**No hace (todavía)**

- No detona malware en una VM: el comportamiento de red es **emulado o inferido**.
- No sustituye a un EDR ni bloquea tráfico en producción.
- No consulta VirusTotal/URLhaus por defecto (`ALLOW_EXTERNAL_INTEL=false`).
- No tiene dashboard web, RBAC ni cola de trabajos distribuida.
- No garantiza detección: declara cobertura y limitaciones, y puede devolver `inconclusive`.

---

## 2. Arquitectura

```
┌──────────────────────────── host Windows (Docker Desktop / WSL2) ────────────────────────────┐
│                                                                                              │
│  navegador / curl                                                                            │
│        │ 127.0.0.1:8000                                                                      │
│        ▼                                                                                     │
│  ┌─────────────────────────────┐        ┌──────────────────────────────┐                     │
│  │ api (FastAPI + CrewAI)      │        │ sandbox-runner               │                     │
│  │ - sin socket Docker         │◄──────►│ - único con socket Docker    │                     │
│  │ - Postgres + /data          │ token  │ - valida imagen y herramienta│                     │
│  └──────────┬──────────────────┘        └──────────────┬───────────────┘                     │
│             │                                          │ docker create/start                │
│             │                                          ▼                                     │
│             │                          ┌────────────────────────────────────────────────┐    │
│             │                          │ worker-pdf / office / js / binary / yara      │    │
│             │                          │ network=none · read-only · cap-drop=ALL       │    │
│             │                          │ user 10001 · pids/mem/cpu limitados           │    │
│             │                          └────────────────────────────────────────────────┘    │
│             │                                                                                │
│    ┌────────▼────────┐    ┌──────────────────┐    ┌─────────────────────┐                    │
│    │ postgres:16     │    │ volumen argos_data│    │ ./reports (bind)    │                    │
│    │ metadatos       │    │ muestras/artefactos│   │ informes generados  │                    │
│    └─────────────────┘    └──────────────────┘    └─────────────────────┘                    │
│                                                                                              │
│  api ── HTTPS ──► api.deepseek.com (solo evidencia sanitizada, jamás la muestra)            │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **api**: FastAPI, pipeline determinista, agentes CrewAI, informes. No tiene el socket de Docker.
- **sandbox-runner**: microservicio interno (puerto 8081, no publicado) que recibe una muestra en
  base64, valida la pareja imagen/herramienta contra una allowlist y crea el worker efímero.
  Es el único servicio con acceso a Docker; está protegido por `RUNNER_SHARED_TOKEN`.
- **workers**: 5 imágenes (pdf, office, js, binary, yara) que ejecutan el análisis y devuelven
  `result.json` + artefactos. El runner los destruye al terminar.
- **postgres**: metadatos, evidencia, investigaciones, IOCs.
- **volumen `argos_data`**: muestras y artefactos; **`./reports`**: informes visibles en el host.

---

## 3. Requisitos

| Requisito | Detalle |
| --- | --- |
| Sistema | Windows 10/11 con Docker Desktop (backend WSL2) o Linux con Docker Engine |
| Docker | 24+ con Compose v2 (`docker compose version`) |
| Recursos | ~2 GB RAM libres y ~3 GB de disco para las imágenes |
| PowerShell | 5.1 o 7+ (los scripts usan `docker` y `docker compose`) |
| DeepSeek | **Opcional**. Sin clave funciona el análisis y el informe determinista; con clave se activan los agentes |
| Python | **No necesario** para usar la pila Docker (solo para desarrollo/tests) |

Comprobación rápida:

```powershell
docker version
docker compose version
```

---

## 4. Puesta en marcha

### 4.1 Arrancar

```powershell
cd C:\Users\oswan\Documents\ARGOS
.\docker\up.ps1
```

El script:

1. Crea `.env.docker` desde `.env.docker.example` si no existe, con un `RUNNER_SHARED_TOKEN`
   aleatorio.
2. Construye las imágenes de workers **solo si faltan** (la primera vez tarda varios minutos).
3. Levanta `postgres`, `sandbox-runner` y `api`, y espera a que estén *healthy*.
4. Imprime las URLs.

Para reconstruir todo (tras cambiar código o Dockerfiles):

```powershell
.\docker\up.ps1 -ForceBuild
```

### 4.2 Activar los agentes (DeepSeek)

Edita `.env.docker` y pon tu clave:

```dotenv
DEEPSEEK_API_KEY=sk-...
CREW_ENABLED=true
CREW_MODEL=deepseek-chat
```

Aplica el cambio recreando la API:

```powershell
docker compose --env-file .env.docker up -d --force-recreate api
```

Sin clave, `llm_configured=false` y el informe se genera con la plantilla determinista
(`llm.status=disabled`). Nada más se degrada.

### 4.3 Comprobar que está vivo

```powershell
curl.exe http://127.0.0.1:8000/health
curl.exe http://127.0.0.1:8000/sandbox-status
```

`/health` (ejemplo resumido):

```json
{
  "status": "ok",
  "version": "0.2.0-sandbox",
  "database": "ok",
  "executor": "runner",
  "runner": { "available": true, "images": { "argos/worker-pdf:0.1.0": true } },
  "llm_configured": true,
  "strict_privacy": true
}
```

`/sandbox-status` confirma el aislamiento:

```json
{
  "executor": "runner",
  "images": { "argos/worker-pdf:0.1.0": true, "...": true },
  "isolation": "network=none, read-only, cap-drop=ALL",
  "note": "La API no tiene socket Docker; sandbox-runner valida y crea workers efímeros."
}
```

### 4.4 Puerto ocupado

Si el 8000 está en uso, cambia en `.env.docker`:

```dotenv
ARGOS_API_PORT=8010
```

y vuelve a ejecutar `.\docker\up.ps1`. La API sigue escuchando solo en `127.0.0.1`.

---

## 5. Uso

### 5.1 Swagger (recomendado)

Abre <http://127.0.0.1:8000/docs>:

1. `POST /malware-samples` → **Try it out**.
2. Selecciona un PDF/DOCM/JS/binario **autorizado**.
3. `wait=true` para esperar el resultado (con agentes puede tardar ~40 s).
4. **Execute** y copia `sample_id` o abre `report_url`.

### 5.2 Subir desde PowerShell

```powershell
curl.exe -X POST "http://127.0.0.1:8000/malware-samples?wait=true" `
  -F "file=@C:\ruta\mi_muestra.pdf"
```

Respuesta:

```json
{
  "sample_id": "smp_eeb42f5d748c4615",
  "sha256": "053146b6fe75d61a...",
  "detected_type": "pdf",
  "deduplicated": true,
  "investigation_id": "inv_a722fda502344567",
  "status": "done",
  "verdict": "malicious",
  "report_url": "/malware-samples/smp_eeb42f5d748c4615/analysis-report"
}
```

### 5.3 Subida asíncrona

`wait=false` (por defecto) devuelve `202` y el análisis corre en segundo plano. Consulta el estado:

```powershell
curl.exe http://127.0.0.1:8000/malware-samples/ID_DE_MUESTRA
```

Cuando `investigation.status` sea `done`, pide el informe:

```powershell
curl.exe http://127.0.0.1:8000/malware-samples/ID_DE_MUESTRA/analysis-report
curl.exe http://127.0.0.1:8000/malware-samples/ID_DE_MUESTRA/analysis-report.md
curl.exe http://127.0.0.1:8000/malware-samples/ID_DE_MUESTRA/analysis-report.html
```

Abre el HTML en el navegador o búscalo en `reports\out\<sha256>.html`.

### 5.4 Demo incluida

Dentro de la API (no requiere instalar nada en el host):

```powershell
docker compose --env-file .env.docker exec -T api python scripts/demo.py
docker compose --env-file .env.docker exec -T api python scripts/demo.py --benign
docker compose --env-file .env.docker exec -T api python scripts/demo.py --docm
```

Para una demo sin coste de LLM:

```powershell
docker compose --env-file .env.docker exec -T -e CREW_ENABLED=false api python scripts/demo.py --benign
```

### 5.5 Informes

Se generan en tres formatos y quedan en el host:

```
reports\out\<sha256>.json   # informe estable, esquema argos.report/1
reports\out\<sha256>.md     # legible
reports\out\<sha256>.html   # presentable
```

Contenido: veredicto, confianza, riesgo, resumen, cadena de ataque, hallazgos con `evidence_id`,
IOCs defanged, MITRE ATT&CK, cobertura (ejecutadas / no disponibles / omitidas), limitaciones,
recomendaciones, herramientas con sus motores y sección de agentes.

---

## 6. Cómo funciona el análisis

1. **Ingesta**: límite de tamaño, SHA-256/MD5, tipo real por firma, deduplicación por hash,
   escritura inmutable en `/data/blobs`.
2. **Agentes (CrewAI)**:
   - **Supervisor** consulta capacidades y ejecuta herramientas con `run_analysis`
     (allowlist por tipo, máximo 4 llamadas, presupuesto).
   - El backend garantiza evidencia: si el supervisor no ejecuta herramientas de contenido,
     corre el plan determinista de respaldo.
3. **Herramientas** en workers Docker: `pdfid`, `pdf_parser`, `office_scan`, `js_analyzer`,
   `shellcode`, `yara`; la reputación local (`intel`) la ejecuta siempre el backend.
4. **Artefactos hijos**: JS extraído, DOCM embebido, macros… se registran como muestras hijas
   (`parent_id`, `depth`) y se analizan hasta `MAX_DEPTH`.
5. **Agregación determinista** (`core/scoring.py`): se toma la mejor evidencia de cada categoría
   (sin doble conteo), con bonus por combinaciones típicas.
   - `malicious` ≥ 6.5 · `suspicious` ≥ 2.0 · `benign` sin hallazgos · `inconclusive` sin cobertura.
6. **Validación y redacción**: el validador busca contradicciones y el redactor escribe el informe.
   El LLM **no** cambia el veredicto ni el riesgo; solo puede ajustar la confianza ±0.05.
7. **Degradación**: si el crew falla o no hay clave, se usa un redactor único; si también falla,
   la plantilla determinista. El análisis siempre termina.

---

## 7. Agentes CrewAI

Dos fases porque la evidencia no existe hasta que el supervisor ejecuta:

```
FASE 1  Supervisor ──► analysis_capabilities(tipo)
                    ──► run_analysis(pdfid | pdf_parser | js_analyzer | office_scan | shellcode | yara)
                    ──► AnalysisPlan
FASE 2  Analista PDF / Office / JS / Shellcode
        Validador de evidencia
        Redactor de informes
```

| Agente | Herramientas | Salida |
| --- | --- | --- |
| Supervisor | `analysis_capabilities`, `run_analysis` | `AnalysisPlan` |
| Analista PDF / Office / JS / Shellcode | — | `FamilyFinding` |
| Validador | — | `ValidationDecision` |
| Redactor | — | `ReportNarrative` |

- Modelo por defecto: **`deepseek-chat`** (alias sin *thinking*). Con `deepseek-flash` el
  razonamiento consumía la respuesta y la API devolvía contenido vacío en prompts largos.
- Coste medido en un PDF sintético: **~58 000 tokens, ~40 s, 6 agentes**.
- Desactivar: `CREW_ENABLED=false` → un solo redactor (~3 000 tokens, ~7 s).

Detalle en [docs/crew.md](docs/crew.md).

---

## 8. Sandbox y aislamiento

Cada herramienta se ejecuta en un contenedor nuevo que muere al terminar:

| Control | Valor |
| --- | --- |
| Red | `network=none` |
| Rootfs | `read_only` |
| Capabilities | `cap_drop=ALL` |
| Escalada | `no-new-privileges` |
| Usuario | `10001:10001` |
| Límites | 768 MB RAM, 1 CPU, 128 PIDs, `nofile=256` |
| Escritura | solo volumen `/out`; muestra en `/work` solo lectura |
| Socket Docker | **no** en workers; solo en `sandbox-runner` |
| Timeout | 60–150 s por herramienta; el runner elimina el contenedor |

La API **nunca** habla con el daemon de Docker. Envía la muestra al runner por HTTP interno con
`X-ARGOS-Runner-Token`; el runner valida que la imagen y la herramienta estén en su allowlist.

Detalle en [docs/sandbox.md](docs/sandbox.md).

---

## 9. Configuración

Todo se configura en `.env.docker` (ignorado por git). Plantilla completa en
`.env.docker.example`.

| Variable | Por defecto | Uso |
| --- | --- | --- |
| `ARGOS_API_PORT` | `8000` | Puerto local de la API (127.0.0.1) |
| `POSTGRES_PASSWORD` | `argos-local-only` | Contraseña de PostgreSQL |
| `RUNNER_SHARED_TOKEN` | generado por `up.ps1` | Token API ↔ sandbox-runner |
| `DEEPSEEK_API_KEY` | vacío | Activa agentes y redacción |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | Endpoint OpenAI-compatible |
| `MODEL_FAST` | `deepseek-flash` | Redactor único / tareas simples |
| `MODEL_DEEP` | `deepseek-v4-pro` | Razonamiento profundo |
| `ENABLE_LLM` | `true` | Interruptor global de LLM |
| `CREW_ENABLED` | `true` | Multiagente CrewAI |
| `CREW_MODEL` | `deepseek-chat` | Modelo de los agentes (sin thinking) |
| `MAX_TOKENS_PER_INVESTIGATION` | `60000` | Presupuesto de tokens |
| `STRICT_PRIVACY` | `true` | Solo hechos sanitizados al LLM |
| `API_KEY` | vacío | Si se define, exige `X-API-Key` |
| `MAX_UPLOAD_MB` | `50` | Tamaño máximo de muestra |
| `MAX_DEPTH` / `MAX_CHILDREN` | `3` / `20` | Recursión de artefactos |
| `MAX_JS_BYTES` / `MAX_STREAMS` | `200000` / `400` | Límites de análisis |
| `ALLOW_EXTERNAL_INTEL` | `false` | Consultas externas (no implementadas) |
| `LOG_LEVEL` | `INFO` | Nivel de log |

> `.env` (sin sufijo) es para desarrollo local con venv; `.env.docker` es para la pila Compose.
> No mezclar: Compose solo lee el que se pasa con `--env-file`.
>
> Si cambias `POSTGRES_PASSWORD` después del primer arranque, el volumen conserva la contraseña
> anterior: usa `.\docker\down.ps1 -DeleteData` (borra datos) o cámbiala dentro de PostgreSQL.

---

## 10. API REST

| Método | Ruta canónica | Descripción |
| --- | --- | --- |
| POST | `/malware-samples?wait=false` | Sube una muestra de malware; `202` y análisis en segundo plano |
| GET | `/malware-samples` | Últimas muestras de malware analizadas |
| GET | `/malware-samples/{sample_id}` | Metadatos de la muestra, árbol de artefactos y estado |
| GET | `/malware-samples/{sample_id}/analysis-report` | Informe de análisis en JSON |
| GET | `/malware-samples/{sample_id}/analysis-report.md` | Informe en Markdown |
| GET | `/malware-samples/{sample_id}/analysis-report.html` | Informe en HTML |
| GET | `/indicators-of-compromise?value=` | Búsqueda de IOCs (hash, dominio, URL, IP, correo) |
| GET | `/analysis-tools` | Catálogo de herramientas, versión e imagen de sandbox |
| GET | `/sandbox-status` | Estado del runner y perfil de aislamiento |
| GET | `/health` | Salud de DB, LLM y sandbox |
| GET | `/analysis-statistics` | Contadores y distribución de veredictos |
| POST | `/llm/connection-test` | Comprueba la conexión con DeepSeek |

Rutas antiguas (`/samples`, `/samples/{id}/report`, `/iocs`, `/tools`, `/sandbox`, `/stats`,
`/llm/ping`) siguen funcionando como alias ocultos para no romper clientes, pero **no aparecen en
Swagger**: usa siempre las rutas canónicas.

Autenticación opcional: si `API_KEY` no está vacío, las rutas de datos requieren el header
`X-API-Key` (`/`, `/health`, `/docs` y `/openapi.json` quedan públicos).

---

## 11. Datos y persistencia

| Dato | Dónde | Se borra con |
| --- | --- | --- |
| PostgreSQL (metadatos, evidencia, IOCs) | volumen `argos_pg` | `down.ps1 -DeleteData` |
| Muestras y artefactos | volumen `argos_data` (`/data/blobs`) | `down.ps1 -DeleteData` |
| Informes | `.\reports\out\` (bind mount) | manual |
| Imágenes de workers | Docker local | `docker image rm ...` |

`down.ps1` sin `-DeleteData` conserva ambos volúmenes: al volver a arrancar, las muestras
anteriores siguen ahí y se deduplican por SHA-256.

---

## 12. Operación diaria

```powershell
# estado
docker compose --env-file .env.docker ps

# logs
docker compose --env-file .env.docker logs -f api
docker compose --env-file .env.docker logs -f sandbox-runner

# reiniciar la API tras cambiar .env.docker
docker compose --env-file .env.docker up -d --force-recreate api

# reconstruir tras cambiar código o Dockerfiles
.\docker\up.ps1 -ForceBuild

# parar (conserva datos)
.\docker\down.ps1

# parar y borrar PostgreSQL + muestras
.\docker\down.ps1 -DeleteData
```

Los contenedores usan `restart` de Compose (no `always`): si reinicias Docker Desktop, ejecuta
`.\docker\up.ps1` de nuevo.

---

## 13. Tests y calidad

En el host (requiere Python 3.12 + venv):

```powershell
uv venv .venv --python 3.12
uv pip install --python .venv\Scripts\python.exe -e ".[dev,llm,crew,yara,office,binary]"
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check .
```

Estado actual: **47 tests** (adaptadores, sanitización, política, scoring, pipeline, API,
contrato de workers, ejecución real en Docker y CrewAI con LLM simulado). Los tests de Docker y
runner se saltan si no hay daemon o imágenes.

La imagen `api` no incluye `pytest`: los tests se ejecutan en el host o en CI, no en producción.

---

## 14. Estructura del repositorio

```
ARGOS/
├── api/                  FastAPI: rutas, seguridad
├── agents/               CrewAI: crew.py, tools.py, schemas.py
├── core/                 settings, db, ingest, storage, sanitizer, policy, scoring, llm, report
├── graphs/               pipeline de investigación (dos fases + fallback)
├── tools/
│   ├── registry.py       allowlist, presupuesto, versiones, dispatch
│   ├── adapters/         pdfid, pdf_parser, office, js, shellcode, yara, intel
│   └── executors/        docker_exec.py (host), runner_exec.py (Compose), in-process
├── workers/              entry.py (contrato del worker), enrich.py, engines
├── runner/               microservicio con socket Docker (sandbox-runner)
├── docker/               Dockerfiles, build.ps1, up.ps1, down.ps1
├── scripts/              demo.py, probe_tools.py, ping_deepseek.py, ping_crew.py, probe_models.py
├── tests/                unitarios, integración, fixtures sintéticas
├── docs/                 arquitectura, CrewAI, sandbox, seguridad, DeepSeek, MVP, backlog
├── data/                 seed de intel (los blobs viven en el volumen Docker)
├── reports/              informes generados (bind mount)
├── docker-compose.yml    api + postgres + sandbox-runner + workers (perfil build)
├── .env.docker.example   plantilla de configuración de la pila
└── pyproject.toml        dependencias y configuración de tests/lint
```

---

## 15. Seguridad y límites

- **Aislamiento real de workers**: sin red, sin root, rootfs de solo lectura, capabilities
  eliminadas, límites de recursos y sin socket Docker.
- **La API no puede crear contenedores**: solo el runner, autenticado por token y en la red
  interna de Compose. El runner no está publicado al host.
- **Muestras**: se guardan en un volumen; la API no las sirve por HTTP (solo metadatos e informe).
- **LLM**: recibe únicamente evidencia sanitizada (hashes, descripciones, IOCs defanged);
  nunca bytes, rutas, secretos ni código completo. `STRICT_PRIVACY=true` por defecto.
- **Prompt injection**: el contenido de la muestra se delimita como dato no confiable y el LLM
  no tiene capacidad de acción (solo JSON validado; el backend autoriza).
- **API**: escucha solo en `127.0.0.1`; `API_KEY` opcional para añadir autenticación.
- **Rotación de claves**: si una `DEEPSEEK_API_KEY` se comparte o se pega en un chat, revócala y
  genera otra. Nunca la pongas en `.env.docker.example` ni en un commit.
- **Límites que debes conocer**:
  - Docker comparte kernel con Windows: es una barrera de *parsing*, **no** de detonación.
  - No hay ejecución real de malware: la cadena de ataque es en parte inferida.
  - `box-js` puede fallar en scripts complejos; el informe lo marca como `partial`.
  - Un PDF/JS muy pesado puede agotar el timeout y devolver cobertura parcial.
  - Falsos positivos/negativos posibles; el veredicto declara confianza y limitaciones.

---

## 16. Estado y roadmap

**Implementado**

- Ingesta, cuarentena, hashes, deduplicación.
- Triage, PDF, Office, JS, shellcode, YARA, intel local.
- Recursión padre-hijo y presupuesto por investigación.
- CrewAI (6 agentes) + DeepSeek, con degradación a redactor único y plantilla.
- Sandbox Docker con `runner` (API sin socket) y 5 imágenes.
- PostgreSQL, volúmenes persistentes, informes JSON/MD/HTML.
- API REST, Swagger, `/health`, `/sandbox-status`, `/analysis-statistics`, `/analysis-tools`.
- 47 tests y lint limpio.

**Pendiente**

| Fase | Estado |
| --- | --- |
| Cola distribuida Celery/Redis | No implementada; hoy `BackgroundTasks` dentro de la API |
| MinIO/S3 para muestras | No implementado; volumen local + almacenamiento abstraído |
| Threat intel externo (VT, URLhaus, MISP) | No implementado; solo seed local |
| Herramientas legacy (peepdf, Origami, OfficeMalScanner) | No integradas |
| Detonación real en VM (CAPE/INetSim) | Fuera de alcance actual; requiere hipervisor separado |
| Dashboard, RBAC, OpenTelemetry/Grafana | No implementados |

---

## 17. Solución de problemas

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| `required variable RUNNER_SHARED_TOKEN is missing` | Ejecutaste `docker compose` sin `--env-file` | Usa `--env-file .env.docker` o `.\docker\up.ps1` |
| `api` reinicia o `Exited` | PostgreSQL no listo / `DATABASE_URL` mal | `docker compose --env-file .env.docker logs api` y `logs postgres` |
| `/health` responde `degraded` | DB caída | Reinicia `postgres`; revisa el volumen `argos_pg` |
| `/sandbox-status` con `available:false` | Runner caído o token distinto | `logs sandbox-runner`; regenera `RUNNER_SHARED_TOKEN` y recrea ambos |
| Herramientas `unavailable` | Imágenes de workers ausentes | `.\docker\up.ps1 -ForceBuild` |
| Crew muy lento o caro | 6 llamadas a DeepSeek | `CREW_ENABLED=false` y recrea `api` |
| `EmptyLLMResponseError` | Modelo con *thinking* y prompt largo | Usa `CREW_MODEL=deepseek-chat` (por defecto) |
| `401 Unauthorized` | `API_KEY` definido | Envía `X-API-Key: <valor>` |
| Puerto 8000 ocupado | Otro servicio | `ARGOS_API_PORT=8010` y `up.ps1` |
| Docker Desktop apagado | Daemon no accesible | Inícialo y repite `up.ps1` |
| Quiero borrar todo | — | `.\docker\down.ps1 -DeleteData` (perderás muestras e informes de DB) |

Diagnóstico rápido:

```powershell
docker compose --env-file .env.docker ps
docker compose --env-file .env.docker logs --tail 80 api
docker compose --env-file .env.docker exec api python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())"
```

---

## 18. Documentación

| Documento | Contenido |
| --- | --- |
| [docs/arquitectura.md](docs/arquitectura.md) | Arquitectura actual: Compose, runner, pipeline, agentes, datos |
| [docs/crew.md](docs/crew.md) | Agentes CrewAI: dos fases, guardarraíles, modelo y costes |
| [docs/sandbox.md](docs/sandbox.md) | Aislamiento, imágenes, runner y contrato worker ↔ host |
| [docs/deepseek.md](docs/deepseek.md) | Integración con DeepSeek, modelos, privacidad y verificación |
| [docs/seguridad.md](docs/seguridad.md) | Modelo de amenazas del laboratorio y controles |
| [docs/mvp.md](docs/mvp.md) | Alcance implementado, desviaciones y límites |
| [docs/backlog.md](docs/backlog.md) | Épicas e historias por fase (planificación) |
| [PLAN.md](PLAN.md) | Plan maestro original (histórico) |

---

## Aviso

ARGOS es una herramienta de laboratorio. Analiza únicamente muestras propias o de fuentes
autorizadas, no redistribuyas malware y no lo detones fuera de una VM desechable y aislada.
El sandbox reduce el riesgo de *parsing*, no convierte a Docker en una frontera de seguridad
para ejecución de código malicioso.

