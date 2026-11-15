# ARGOS — Plan maestro

> **Documento histórico (v1.0).** Describe el diseño inicial con LangGraph/MCP. La implementación
> actual usa **CrewAI** y un **sandbox-runner** Docker; consulta [README.md](README.md) y
> [docs/arquitectura.md](docs/arquitectura.md) para el estado real.

**Plataforma multiagente de análisis de malware para PDF, Office, JavaScript y shellcode**

| Campo | Valor |
| --- | --- |
| Nombre del proyecto | **ARGOS** |
| Nombre técnico / repo | `argos` |
| Carpeta | `C:\Users\oswan\Documents\ARGOS` |
| Versión del plan | 1.0 |
| Fecha | 2026-11-15 |
| Autor | Oswaldo (operador del laboratorio) |
| Estado | Planificación (Fase 0) |
| Modelo de IA | DeepSeek API — `deepseek-flash` / `deepseek-v4-pro` |

---

## 1. Nombre y visión

**ARGOS** toma el nombre del gigante de cien ojos de la mitología griega: un solo caso, muchos
agentes mirándolo desde ángulos distintos (documento, código, binario, red, reputación) y un
observador central que integra todo en una conclusión explicable.

**Visión:** convertir el análisis de malware de una tarea artesanal de "abrir herramientas y mirar"
en una **investigación reproducible, auditable y explicada**: cada hallazgo tiene una evidencia
asociada, cada conclusión tiene un nivel de confianza y cada límite del análisis se declara.

**Propuesta de valor**

1. Un PDF sospechoso entra por la API y sale un informe que explica *cómo* funcionaría el ataque,
   no solo *que* es malicioso.
2. El analista humano puede revisar, corregir y aprobar en mitad del flujo (human-in-the-loop).
3. Todo el conocimiento queda en una memoria de investigaciones: hashes, IOCs, relaciones
   padre-hijo entre archivos, patrones ya vistos.
4. El LLM nunca toca la muestra directamente: recibe evidencia estructurada y sanitizada.

**No objetivos (v1):** no es un EDR, no es un antivirus, no bloquea tráfico en producción, no
detona malware en el host del analista, no promete detección perfecta.

---

## 2. Alcance

### Incluido en v1 (fases 1–5)

| Capacidad | Detalle |
| --- | --- |
| Ingesta | Subida por API REST, límite de tamaño, hash SHA-256, detección real de tipo por firma |
| Cuarentena | Almacenamiento inmutable en MinIO, nombre por hash, sin ejecución |
| Análisis PDF | PDFiD (clasificación), pdf-parser (objetos, streams, `/JS`, `/OpenAction`, `/EmbeddedFile`), YARA |
| Análisis Office | olevba / oletools (macros VBA, XLM, autoexec, IOCs), oleobj (objetos embebidos) |
| Análisis JavaScript | Extracción sin ejecución, AST (acorn/esprima), deobfuscación básica, emulación con box-js |
| Análisis shellcode | Detección de arquitectura, desensamblado con Capstone, extracción de cadenas/llamadas |
| Threat intel | VirusTotal, MalwareBazaar, URLhaus, MISP local — solo consulta de IOCs, nunca descarga |
| Correlación | Cruce de evidencias, relaciones padre-hijo, deduplicación por hash |
| Informe | Veredicto + confianza, IOCs, MITRE ATT&CK, cadena de ataque, evidencias citadas, limitaciones; JSON y PDF |
| Agentes | Supervisor LangGraph + especialistas PDF, Office, JS, shellcode, IOC, validador, redactor |

### Fuera de v1 (fases 6–7)

- Detonación real en VM (CAPE) — Fase 6, en hipervisor separado.
- Análisis profundo de PE/ELF más allá de triage (Ghidra headless, LIEF avanzado).
- Dashboard React completo, multi-tenant, RBAC fino, SSO.
- Generación automática de reglas YARA publicables (se propone, no se publica).
- Entrenamiento o fine-tuning de modelos.

---

## 3. Principios de diseño

1. **El LLM decide, el backend ejecuta.** El modelo solo puede llamar herramientas MCP con
   contratos tipados. No tiene shell, ni acceso a Docker, ni a la red.
2. **Separación de zonas.** Control (API, agentes, BD) ≠ análisis estático (containers) ≠
   detonación (VMs). Ninguna zona confía en la anterior.
3. **Evidencia primero.** Todo hallazgo referencia un `evidence_id` con su origen (herramienta,
   objeto, offset, hash). Sin evidencia no hay afirmación.
4. **Determinismo donde se pueda.** La clasificación, el hashing, YARA y la extracción son
   deterministas; el LLM se usa para interpretar, priorizar y redactar, no para "adivinar".
5. **Confianza calibrada.** El informe declara qué se comprobó, qué se infirió y qué no se pudo
   comprobar. "Sospechoso" ≠ "malicioso confirmado".
6. **Privacidad por defecto.** Al proveedor LLM solo viaja evidencia sanitizada (URLs defanged,
   sin bytes, sin rutas personales, sin secretos).
7. **Reproducibilidad.** Misma muestra + misma versión de herramientas + mismo prompt ⇒ mismo
   informe (salvo el texto generado, que se versiona).
8. **Límites explícitos.** Profundidad de recursión, tamaño, tiempo de CPU y tokens por
   investigación están acotados y se registran.
9. **Todo es observable.** Trazas OpenTelemetry por investigación, costo por token, latencia por
   herramienta, decisiones del agente registradas.
10. **Seguro por defecto.** Contenedores sin privilegios, sin red salvo lo imprescindible,
    `read_only`, `cap_drop: ALL`, seccomp; denegación por defecto en la política de herramientas.

---

## 4. Decisiones de arquitectura (ADR resumidas)

| # | Decisión | Alternativa descartada | Motivo |
| --- | --- | --- | --- |
| ADR-01 | DeepSeek API como LLM principal | Ollama local desde el día 1 | El usuario ya opera con DeepSeek; costo bajo, 1M de contexto, tool calling y JSON mode. La abstracción de proveedor deja la puerta abierta a local. |
| ADR-02 | `deepseek-flash` por defecto, `deepseek-v4-pro` bajo demanda | Un solo modelo | 90 % de los pasos son mecánicos (clasificar, resumir, redactar). El modelo caro se reserva al validador y a casos ambiguos. |
| ADR-03 | LangGraph para orquestación | CrewAI / AutoGen / cadena ad-hoc | Estado tipado, checkpoints, ramas condicionales, interrupción para aprobación humana y reanudación. |
| ADR-04 | Servidores MCP internos como única vía de acceso a herramientas | Darle al agente una tool de shell | Contratos tipados, autorización por herramienta, aislamiento y trazabilidad. |
| ADR-05 | Workers Docker por herramienta | Una imagen monolítica | Dependencias incompatibles (Python 3.x vs Node), superficie de ataque menor, versionado independiente. |
| ADR-06 | MinIO + PostgreSQL + Redis | Solo filesystem / SQLite | Evidencia inmutable, metadatos consultables, cola de trabajos con reintentos. |
| ADR-07 | Observabilidad self-hosted (OTel + Langfuse + Grafana) | LangSmith cloud | Las trazas contienen datos de muestras; no deben salir de la zona de control. |
| ADR-08 | Redacción/sanitización antes del LLM | Enviar el script completo | Privacidad, costo y resistencia a prompt injection desde el propio malware. |
| ADR-09 | Detonación solo en VM separada, nunca en el host | "Sandbox" en contenedor | Un contenedor no es frontera de seguridad para malware activo. |
| ADR-10 | Python 3.12 + FastAPI + Pydantic v2 | Django / Node | Ecosistema de análisis (oletools, yara-python, capstone, lief) es Python. |

---

## 5. Fases, entregables y criterios de aceptación

> Estimación asumiendo **un desarrollador, 10–12 h/semana**. Si se dedica tiempo completo,
> dividir por ~2.5.

### Fase 0 — Fundaciones (semana 1)

**Objetivo:** que el repositorio arranque y que la decisión de IA esté probada de punta a punta.

Entregables:
- Estructura de carpetas (ya creada), `pyproject.toml`, `ruff`, `pytest`, `pre-commit`.
- `docker-compose.dev.yml` con Postgres, Redis, MinIO.
- Módulo `core/llm.py`: cliente DeepSeek con reintentos, timeout, presupuesto de tokens y logging.
- Script `scripts/ping_deepseek.py`: una llamada real con tool calling y salida JSON validada por Pydantic.
- `.env.example` y gestión de secretos.

Criterios de aceptación:
- [ ] `pytest` corre en verde (aunque sea con 3 tests triviales).
- [ ] El script de ping obtiene una respuesta con `tool_calls` y la valida contra un esquema.
- [ ] `docker compose up` levanta Postgres/Redis/MinIO y el healthcheck pasa.
- [ ] El costo de la llamada de prueba queda registrado en el log.

### Fase 1 — Ingesta, cuarentena y clasificación (semanas 2–4)

**Objetivo:** subir un archivo y obtener clasificación determinista.

Entregables:
- `api/`: `POST /samples`, `GET /samples/{id}`, `GET /samples/{id}/report`.
- Ingesta: límite de tamaño configurable, cálculo de SHA-256/MD5, detección de tipo real
  (magic bytes + `python-magic`), rechazo de tipos no soportados, escritura inmutable en MinIO.
- Worker YARA (`workers/yara`) con reglas propias + reglas de la comunidad seleccionadas.
- Worker `pdf_tools`: PDFiD como primera pasada.
- Persistencia: tablas `samples`, `analyses`, `evidence`, `artifacts`.
- Cola Celery + Redis con reintentos y dead-letter.

Criterios de aceptación:
- [ ] Subir un PDF benigno de prueba devuelve 202 y un `sample_id`.
- [ ] Un archivo de 200 MB es rechazado con error claro (límite 50 MB por defecto).
- [ ] Un `.exe` renombrado a `.pdf` se detecta como PE por firma y se rechaza o se deriva a triage binario.
- [ ] El mismo archivo subido dos veces devuelve el mismo `sample_id` (deduplicación por SHA-256).
- [ ] Ejecutar YARA sobre un corpus de 20 archivos benignos no produce falsos positivos.
- [ ] Cobertura de tests ≥ 60 % en `api/` y `core/`.

### Fase 2 — Análisis PDF y Office (semanas 5–7)

**Objetivo:** entender el documento, no solo clasificarlo.

Entregables:
- MCP `pdf-tools-mcp`: `scan_pdf`, `inspect_pdf_object`, `extract_pdf_streams`, `list_embedded_files`.
- MCP `office-tools-mcp`: `extract_vba`, `inspect_ole`, `detect_autoexec`, `extract_embedded`.
- Extracción de artefactos hijos: JS de PDF, macros, OLE objects, adjuntos → nuevo `sample` hijo con
  relación `parent_id` y profundidad máxima 3.
- Primer agente LLM real: `pdf_agent` y `office_agent` que interpretan el JSON de las herramientas y
  proponen siguientes pasos (sin ejecutarlos aún).

Criterios de aceptación:
- [ ] Un PDF con `/OpenAction` + `/JavaScript` produce hallazgos con `object_id` y `evidence_id`.
- [ ] Un DOCM de laboratorio con macro `AutoOpen` produce la macro extraída y los IOCs detectados.
- [ ] Un PDF con un DOCX embebido genera un sample hijo y se analiza en cadena.
- [ ] Ninguna herramienta recibe rutas fuera del directorio de trabajo del worker.
- [ ] Todos los resultados de herramienta validan contra su esquema Pydantic.

### Fase 3 — JavaScript y shellcode (semanas 8–10)

**Objetivo:** analizar el código extraído sin ejecutarlo en el host.

Entregables:
- MCP `javascript-mcp`: `parse_js_ast`, `deobfuscate_js`, `analyze_js` (box-js en worker Node aislado),
  `extract_js_iocs`.
- MCP `binary-mcp`: `detect_architecture`, `disassemble` (Capstone), `extract_strings`, `entropy_map`.
- Sandboxing de box-js: contenedor sin red, timeout duro, límite de memoria, salida capturada a JSON.
- Detección de llamadas peligrosas (`WScript.Shell`, `ADODB.Stream`, `MSXML2.XMLHTTP`, `eval`,
  `ActiveXObject`) y extracción de URLs con defanging.

Criterios de aceptación:
- [ ] Un JS ofuscado de laboratorio se desofusca y produce al menos 1 URL y 1 API peligrosa.
- [ ] box-js con un script que intenta `while(true)` termina por timeout sin colgar el worker.
- [ ] box-js no tiene salida a Internet (test con `curl` dentro del contenedor → falla).
- [ ] Un blob de shellcode x86 produce arquitectura detectada y ≥ 20 instrucciones desensambladas.
- [ ] El informe incluye los IOCs del JS con `hxxp://` (defanged).

### Fase 4 — Orquestación LangGraph + MCP (semanas 11–13)

**Objetivo:** el supervisor decide la ruta y los especialistas colaboran.

Entregables:
- Grafo LangGraph: `ingest → triage → route → {pdf|office|js|shellcode} → intel → correlate → validate → report`.
- Estado tipado (`InvestigationState`) con checkpointer Postgres; reanudación tras fallo.
- `policy_engine`: qué herramienta puede ejecutarse para qué tipo de muestra y con qué límites.
- Human-in-the-loop: interrupción antes de detonación y antes de publicar un veredicto "malicioso"
  cuando la confianza es media.
- Presupuesto por investigación (tokens, tiempo, llamadas a herramientas) y corte limpio al excederlo.

Criterios de aceptación:
- [ ] Un PDF sigue la ruta `pdf → js → intel → validate → report` sin intervención.
- [ ] Un archivo no reconocido termina en `unsupported` con mensaje claro, sin gastar tokens.
- [ ] Si una herramienta falla, el grafo reintenta una vez y luego degrada el informe (no explota).
- [ ] Una investigación se reanuda desde el checkpoint después de reiniciar el worker.
- [ ] El costo total en tokens por investigación queda registrado y es < 150k tokens en el caso PDF típico.

### Fase 5 — Threat intel, correlación y reportes (semanas 14–16)

**Objetivo:** informe final publicable.

Entregables:
- `threat_intel-mcp`: `lookup_hash`, `lookup_domain`, `lookup_ip`, `lookup_url` con caché (24 h),
  rate limiting y modo offline (solo MISP/base local).
- Motor de correlación: similitud por hashes, IOCs compartidos, familias, campañas; "¿ya vi esto?".
- Generador de informe: plantilla Jinja2 → HTML → PDF (WeasyPrint) + JSON estable (schema versionado).
- Mapeo MITRE ATT&CK por técnica observada (tabla propia, sin inventar IDs).
- Memoria de investigaciones: tabla `iocs`, `relations`, `campaigns`, búsqueda por IOC.

Criterios de aceptación:
- [ ] Un IOC visto en dos muestras distintas aparece relacionado en el informe.
- [ ] El JSON del informe valida contra `report.schema.json` y es estable entre ejecuciones.
- [ ] El PDF se genera en < 10 s y cita cada evidencia con su `evidence_id`.
- [ ] Sin claves de terceros, el sistema funciona en modo offline y lo declara en el informe.

### Fase 6 — Detonación controlada (semanas 17–20, opcional)

**Objetivo:** comportamiento real, en un entorno que no puede tocar la red real.

Entregables:
- `sandbox/vm_controller`: API para solicitar detonación (solo con aprobación humana).
- VM Windows desechable + snapshot + reversión; red simulada (INetSim o similar); CAPE como backend.
- Transferencia de muestras por servicio intermediario (no montar el almacén en la VM).
- Correlación de comportamiento con el análisis estático (¿la URL estática apareció en red?).

Criterios de aceptación:
- [ ] La VM no alcanza la red doméstica ni Internet (prueba desde dentro).
- [ ] Tras cada detonación la VM vuelve al snapshot verificablemente (hash del disco).
- [ ] El informe distingue "observado en emulación" de "observado en ejecución real".

### Fase 7 — Operación (semanas 21–24)

- Dashboard React (lista de investigaciones, detalle, IOCs, costo, latencia).
- Métricas: precisión sobre corpus benigno, tasa de falsos positivos, tiempo medio por caso.
- Auditoría: quién subió qué, quién aprobó qué, qué versión de reglas se usó.
- Backups, retención, borrado seguro de muestras.

---

## 6. Cronograma

| Semana | Fase | Hito |
| --- | --- | --- |
| 1 | 0 | Repo + compose + ping DeepSeek con tool calling |
| 2–4 | 1 | Subida, cuarentena, hash, YARA, PDFiD |
| 5–7 | 2 | PDF y Office con evidencia estructurada |
| 8–10 | 3 | JS (box-js) y shellcode (Capstone) |
| 11–13 | 4 | LangGraph + MCP + aprobación humana |
| 14–16 | 5 | IOC, correlación, informe JSON/PDF |
| 17–20 | 6 | Detonación en VM (opcional) |
| 21–24 | 7 | Dashboard y operación |

**Primer hito demostrable: fin de semana 7** — "subo un PDF, veo los objetos sospechosos y un
informe preliminar". Ese es el corte mínimo para decidir si el proyecto sigue.

---

## 7. Presupuesto estimado

### Infraestructura (desarrollo local)

| Recurso | Costo |
| --- | --- |
| Docker Desktop + WSL2 | 0 (licencia personal) |
| Postgres/Redis/MinIO en local | 0 |
| VM de detonación (Fase 6) | 0 si es local con Hyper-V/VirtualBox; ~US$20–40/mes si es cloud aislada |
| Corpus de pruebas | 0 (malware samples públicos + archivos de laboratorio propios) |

### API DeepSeek (orden de magnitud, verificar tarifa vigente)

Precios publicados en CNY por millón de tokens (noviembre 2026), con descuento fuera de hora punta
y ~90 % de descuento en caché de contexto:

| Modelo | Entrada (cache miss) | Salida |
| --- | --- | --- |
| `deepseek-flash` | 1–2 CNY | 4–8 CNY |
| `deepseek-v4-pro` | 4.5–9 CNY | 13.5–27 CNY |

Estimación de una investigación PDF típica (≈120k tokens de entrada + 15k de salida, mayormente
`flash`): **≈0.20 CNY (≈US$0.03)**. Mil investigaciones al mes: **≈200 CNY (≈US$30)**.
El validador con `v4-pro` en el 10 % de los casos añade un 15–25 %.

> Estas cifras son de planificación, no una cotización. La tarifa y los nombres de modelo cambian:
> confirmar en https://api-docs.deepseek.com/quick_start/pricing antes de comprometer volumen.

---

## 8. Riesgos

| Riesgo | Prob. | Impacto | Mitigación |
| --- | --- | --- | --- |
| Fuga de datos de la muestra al proveedor LLM | Media | Alto | Sanitización obligatoria, sin bytes crudos, sin URLs vivas, revisión de términos; opción local |
| Prompt injection desde el propio malware (texto que instruye al LLM) | Alta | Alto | Contenido de muestra tratado como datos delimitados; el LLM no puede ejecutar nada; validación de esquemas y política de herramientas |
| Escape del contenedor / infección del host | Baja | Crítico | Sin red, sin privilegios, `read_only`, seccomp; nunca detonar en el host; snapshots |
| Costo de API descontrolado | Media | Medio | Presupuesto por investigación, caché, routing a `flash`, alertas |
| box-js / oletools rompen con muestras raras | Alta | Medio | Timeouts, degradación elegante, versión pinneada, tests con corpus |
| Falsos positivos que erosionan la confianza | Alta | Alto | Corpus benigno obligatorio, veredicto con confianza, revisión humana |
| Alcance se dispara (querer todo a la vez) | Alta | Alto | Fases con criterios de aceptación; hito de la semana 7 |
| API DeepSeek inestable (503) | Media | Medio | Reintentos con backoff, cola, fallback a proveedor alterno configurable |
| Legal: manejo de malware | Baja | Alto | Solo muestras autorizadas; no contactar infraestructura; no redistribuir |
| Dependencia de un solo desarrollador | Alta | Medio | Documentación viva, tests, contenedores reproducibles |

---

## 9. Métricas de éxito

| Métrica | Objetivo v1 |
| --- | --- |
| Tiempo medio de investigación automática (PDF) | < 3 min |
| Costo medio por investigación | < 0.5 CNY |
| Falsos positivos sobre corpus benigno (50 archivos) | < 5 % |
| Cobertura de evidencias citadas en el informe | 100 % de las afirmaciones con `evidence_id` |
| Investigaciones reanudables tras fallo | 100 % |
| Precisión del veredicto vs. analista humano (muestra de 20 casos) | ≥ 80 % de acuerdo |

---

## 10. Requisitos del entorno (verificados en esta máquina)

| Componente | Estado | Nota |
| --- | --- | --- |
| Windows + PowerShell | OK | `C:\Users\oswan\Documents` |
| Python | OK (`py` launcher; venv de Hermes en PATH) | Crear venv propio del proyecto |
| Node.js | OK (`C:\Program Files\nodejs`) | Necesario para box-js |
| Docker | OK (`C:\Program Files\Docker`) | Verificar backend WSL2 |
| git | OK | |
| Ollama | **No instalado** | No es requisito: el LLM es DeepSeek API |

Pendiente de instalar en Fase 0: `uv` (o `pipx`), dependencias Python del proyecto, `yara-python`
(requiere build tools en Windows → se ejecuta dentro de contenedor Linux), y claves de API.

> Nota importante para Windows: `yara-python`, oletools y las herramientas de PDF se ejecutan en
> **contenedores Linux**. En el host solo corre la API, el orquestador y los tests unitarios puros.

---

## 11. Próximos pasos inmediatos (checklist semana 1)

1. [ ] Verificar `docker info` y el backend WSL2.
2. [ ] Crear `.env` desde `.env.example` y guardar `DEEPSEEK_API_KEY`.
3. [ ] Crear el venv con `uv venv` e instalar `fastapi`, `pydantic`, `openai`, `langgraph`,
       `langchain-deepseek`, `langchain-mcp-adapters`, `sqlalchemy`, `alembic`, `celery`, `redis`,
       `boto3`, `opentelemetry-*`, `pytest`, `ruff`.
4. [ ] Implementar `core/llm.py` + `scripts/ping_deepseek.py` y ejecutarlo (Fase 0, criterio 1).
5. [ ] `docker compose up -d` con Postgres/Redis/MinIO y verificar healthchecks.
6. [ ] Escribir `docs/decisiones.md` con las ADR de la sección 4 (formato corto).
7. [ ] Descargar 20 archivos benignos variados (PDFs, DOCX, JS) para el corpus de línea base.

---

## 12. Decisiones pendientes (con valor por defecto ya elegido)

| Tema | Valor por defecto | Cuándo revisar |
| --- | --- | --- |
| Nombre definitivo | ARGOS (cambiable; solo afecta branding y carpeta) | Antes de publicar |
| Modelo por defecto | `deepseek-flash` | Si la calidad del informe decepciona |
| ¿Modelo local de respaldo? | No en v1; abstracción lista | Si hay requisito de confidencialidad |
| Backend de cola | Celery (como en el diseño original) | Si se prefiere `arq` por simplicidad async |
| Dashboard | React en Fase 7 | Si se necesita antes para demo |
| Detonación | Fase 6, hipervisor aparte | Solo si hay presupuesto y necesidad real |
| Idioma de los informes | Español, con IOCs y términos técnicos en inglés | Si se comparte con terceros |
