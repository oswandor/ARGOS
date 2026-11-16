# ARGOS — Alcance implementado (v0.2.0)

Estado real del sistema desplegado con Docker Compose. Sustituye al documento de MVP inicial.

## 1. Qué está implementado

| Área | Implementación | Estado |
| --- | --- | --- |
| Ingesta | `core/ingest.py` | límite, SHA-256/MD5, tipo real, dedupe, cuarentena |
| Almacenamiento | `core/storage.py` + volumen `argos_data` | interfaz lista para MinIO/S3 |
| Base de datos | PostgreSQL 16 en Compose (`argos_pg`) | SQLite sigue disponible para desarrollo |
| API | FastAPI + Swagger, `/health`, `/sandbox-status`, `/analysis-tools`, `/analysis-statistics` | sin socket Docker |
| Sandbox | `sandbox-runner` + 5 workers | `network=none`, read-only, cap-drop ALL, uid 10001 |
| Registro de herramientas | `tools/registry.py` | allowlist, presupuesto, versiones, dispatch runner/docker/inprocess |
| PDF | PDFiD + pdf-parser (Didier Stevens), qpdf, pypdf, parser propio | objetos, streams, `/JS`, embebidos |
| Office | oletools (olevba/oleobj/mraptor), olefile, msoffcrypto | macros, AutoOpen, objetos embebidos |
| JavaScript | box-js + analizador estático | emulación, `IOC.json`, archivos generados |
| Shellcode | Capstone, LIEF, objdump, nasm | arquitectura, desensamblado, secciones |
| YARA | yara-python + 7 reglas propias | firmas |
| Threat intel | seed local + tabla `iocs` | sin consultas externas |
| Agentes | CrewAI 1.15, 6 agentes sobre DeepSeek | supervisor, especialistas, validador, redactor |
| Pipeline | `graphs/pipeline.py` | dos fases + respaldo determinista + degradación |
| Informes | JSON (`argos.report/1`), Markdown, HTML | `evidence_id`, IOCs defanged, ATT&CK, cobertura |
| Tests | 46 | unidad, integración, API, workers, Docker, CrewAI simulado |

## 2. Desviaciones respecto al plan 2.0

| Plan 2.0 | Implementación actual | Motivo |
| --- | --- | --- |
| LangGraph | **CrewAI** | Decisión del proyecto; se mantiene el pipeline determinista como respaldo |
| Celery + Redis | `BackgroundTasks` en la API | Un nodo basta; la interfaz de ejecución es sustituible |
| MinIO | Volumen Docker + `Storage` abstracto | Menos piezas; migración sin tocar el pipeline |
| PostgreSQL | **Implementado** en Compose | Persistencia y auditoría |
| 15 herramientas | 6 motores + YARA + intel local | Se integran las que aportan señal; las legacy se declaran no disponibles |
| VM de detonación | No incluida | Requiere hipervisor separado; no se ejecuta malware en este host |
| Dashboard/OTel/RBAC | No incluidos | Fase de operación posterior |

## 3. Matriz de herramientas (estado real)

| Herramienta | Estado | Dónde |
| --- | --- | --- |
| pdfid / pdf-parser (Didier Stevens) | ✅ | `worker-pdf` |
| qpdf, poppler, pypdf, pikepdf | ✅ | `worker-pdf` |
| olevba, oleobj, mraptor (oletools) | ✅ | `worker-office` |
| box-js, jsbeautifier, Node | ✅ | `worker-js` |
| Capstone, LIEF, objdump, nasm | ✅ | `worker-binary` |
| YARA | ✅ | `worker-yara` |
| AnalyzePDF, malpdfobj, PDF X-Ray, peepdf, Origami | ❌ | se declaran no disponibles |
| diStorm, libemu | ❌ | Capstone como alternativa |
| SpiderMonkey | ❌ | box-js cubre la emulación |
| OfficeMalScanner, QuickSand, InQuest | ❌ | requieren Windows/servicio externo |

Ninguna herramienta ausente se presenta como ejecutada: el informe lista `coverage.executed`,
`unavailable` y `skipped`.

## 4. Límites conocidos

- Docker comparte kernel: barrera de *parsing*, no de detonación.
- La cadena de ataque es observada (estático + emulación) e inferida; no hay ejecución real.
- box-js puede fallar en scripts complejos: `partial` y se conservan los IOCs observados.
- oletools necesita un `vbaProject.bin` real; con el fixture sintético no extrae módulos.
- PDFs con xref/object streams comprimidos pueden no exponer objetos internos.
- Un PDF/JS muy grande puede agotar timeout y dejar cobertura parcial.
- Falsos positivos/negativos posibles; el veredicto declara confianza y limitaciones.

## 5. Verificación

- 47 tests (`pytest`) + `ruff` limpio.
- Prueba manual en Compose: subida `wait=true`, informe con 6 agentes (~58k tokens, ~40 s),
  `/sandbox-status` con las 5 imágenes disponibles.
- Demo dentro del contenedor: `docker compose --env-file .env.docker exec -T api python scripts/demo.py`.

## 6. Siguiente fase sugerida

1. Cola real (Celery/Redis) para paralelizar y reintentar sin bloquear la API.
2. MinIO/S3 para muestras y artefactos.
3. Threat intel externo opt-in (hash primero, sin visitar IOCs).
4. Tests adversariales de prompt injection y corpus benigno real.
5. Detonación en VM desechable, fuera de este host.
6. Dashboard, métricas y RBAC.

