# ARGOS — Sandbox Docker

Las herramientas que tocan la muestra se ejecutan en **contenedores efímeros y endurecidos**.
La API no tiene acceso al daemon de Docker: un microservicio interno (`sandbox-runner`) recibe la
muestra, valida la operación y crea el worker.

## 1. Zonas

```
┌──────────────────── api (FastAPI) ────────────────────┐
│ pipeline + CrewAI + informes                          │
│ sin /var/run/docker.sock  ·  sin acceso a workers     │
└───────────────────────┬───────────────────────────────┘
                        │ HTTP interno + X-ARGOS-Runner-Token
                        ▼
┌──────────────── sandbox-runner (8081, no publicado) ───┐
│ allowlist imagen↔herramienta · límites · ciclo de vida │
│ único servicio con /var/run/docker.sock                │
└───────────────────────┬───────────────────────────────┘
                        │ docker create/start/wait/remove
                        ▼
┌──────────────── worker efímero ────────────────────────┐
│ network=none · read-only · cap-drop=ALL · uid 10001    │
│ /work:ro (muestra) · /out:rw (resultado)               │
└────────────────────────────────────────────────────────┘
```

Si el runner cae, las herramientas se reportan `unavailable` y la investigación sigue con lo que
haya (degradación explícita).

## 2. Perfil de aislamiento

| Control | Valor |
| --- | --- |
| `--network none` | sin red |
| `--read-only` | rootfs inmutable |
| `/tmp` tmpfs | `rw,noexec,nosuid,size=64m` |
| `--cap-drop ALL` | sin capabilities |
| `no-new-privileges` | sin escalada |
| `--user 10001:10001` | no root |
| `--pids-limit 128` | anti fork-bomb |
| `--memory 768m --memory-swap 768m` | anti OOM |
| `--cpus 1` | CPU acotada |
| `nofile=256` | FDs acotados |
| montajes | `/work:ro` y `/out:rw` |
| socket Docker | nunca en el worker |
| timeout | 60–150 s por herramienta |

Docker comparte kernel con el host: esto es una barrera de *parsing*, no de detonación. Para
muestras de origen desconocido, los workers deberían correr en una VM Linux dedicada.

## 3. Contrato del runner

API → runner (`POST /v1/run`, header `X-ARGOS-Runner-Token`):

```json
{
  "image": "argos/worker-pdf:0.1.0",
  "tool": "pdfid",
  "detected_type": "pdf",
  "timeout_s": 90,
  "data_b64": "JVBERi0xLjc...",
  "max_artifact_bytes": 5242880,
  "max_js_bytes": 200000,
  "max_streams": 400
}
```

El runner:

1. Exige el token compartido.
2. Comprueba que `(image, tool)` está en su allowlist fija.
3. Crea un volumen de trabajo y otro de salida, copia la muestra con un contenedor auxiliar.
4. Lanza el worker con la política de aislamiento y espera el timeout.
5. Lee `result.json` y los artefactos (con límites de tamaño), y destruye contenedor y volúmenes.
6. Devuelve el JSON tipado a la API.

Endpoints del runner: `/ready` (sonda local de Compose), `/health` (autenticado: imágenes
presentes y aislamiento), `/v1/run`. No está publicado al host.

## 4. Imágenes

| Imagen | Motores |
| --- | --- |
| `argos/worker-pdf` | pdfid.py / pdf-parser.py (Didier Stevens), qpdf, poppler, pypdf, pikepdf |
| `argos/worker-office` | oletools (olevba/oleobj/mraptor), olefile, msoffcrypto |
| `argos/worker-js` | box-js (emulación JScript), jsbeautifier, Node |
| `argos/worker-binary` | Capstone, LIEF, objdump, nasm/ndisasm |
| `argos/worker-yara` | yara-python 4.x |

Cada worker ejecuta el adaptador nativo y, si el motor externo está presente, lo usa para
enriquecer: `engines` en `result.json` declara qué corrió realmente.

## 5. Construcción y arranque

```powershell
# todo (solo construye si faltan imágenes)
.\docker\up.ps1

# reconstruir workers y API tras cambiar código
.\docker\up.ps1 -ForceBuild

# solo workers, manualmente
.\docker\build.ps1
```

El build de `worker-pdf` descarga `pdfid.py` y `pdf-parser.py` de Didier Stevens. Para
reproducibilidad, fija un commit:

```powershell
docker build -f docker/worker-pdf.Dockerfile `
  --build-arg BASE_IMAGE=argos/worker-base:0.1.0 `
  --build-arg DSTEVENS_REF=<commit-sha> `
  -t argos/worker-pdf:0.1.0 .
```

## 6. Verificación

```powershell
curl.exe http://127.0.0.1:8000/sandbox-status
docker compose --env-file .env.docker logs -f sandbox-runner
```

`/sandbox-status` devuelve:

```json
{
  "executor": "runner",
  "images": {"argos/worker-pdf:0.1.0": true, "...": true},
  "isolation": "network=none, read-only, cap-drop=ALL",
  "note": "La API no tiene socket Docker; sandbox-runner valida y crea workers efímeros."
}
```

Tests relevantes:

- `test_run_command_contains_hardening`: valida el argv de `docker run` del modo host.
- `test_pdf_worker_runs_isolated`, `test_yara_worker_runs_isolated`: ejecución real.
- `test_sandbox_blocks_network_access`: el contenedor no abre sockets.
- `test_runner_exec`: contrato runner → `ToolOutput`.
- `test_worker_*`: contrato `entry.py → result.json` sin Docker.

## 7. Contrato del worker

```
python /opt/argos/entry.py <tool> /work/sample.bin --type <tipo> --out /out
```

`/out/result.json`:

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

- stdout no es el canal de resultados (los parsers escriben ahí).
- Los artefactos son nombres planos; se rechazan rutas con `/`, `\` o `..`.
- Sin `result.json`, la API devuelve `status=error` con la cola de logs del worker.

## 8. Añadir una herramienta

1. Adaptador en `tools/adapters/` que devuelva `ToolOutput`.
2. Registro en `tools/bootstrap.py` con `DockerTool(image=..., tool=...)`.
3. Entrada correspondiente en `workers/entry.py` (`TOOLS`) y, si hay binario externo, en
   `workers/enrich.py`.
4. Dependencia en el Dockerfile de la familia.
5. Añadir la pareja imagen/herramienta a `ALLOWED` en `runner/main.py`.
6. Test del adaptador + `scripts/probe_tools.py` en modo runner.

## 9. Límites y riesgos residuales

- Compartición de kernel (ver arriba).
- El runner es una pieza crítica: si se compromete, controla el daemon. Por eso no se publica,
  exige token y solo acepta imágenes/herramientas de su allowlist.
- Un parser puede consumir toda su cuota durante el timeout; está acotado, pero retrasa la
  investigación.
- box-js es antiguo: si falla, se marca `partial` y se conservan los IOCs observados.
- El montaje `/out` es la única escritura; el runner trata su contenido como no confiable.
