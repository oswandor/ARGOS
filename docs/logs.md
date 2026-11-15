# ARGOS — Logs y observabilidad

Qué se registra durante un análisis, cómo verlo en vivo y cómo ajustar el nivel de detalle.

## 1. Ver logs en directo

```powershell
# API: pipeline, agentes, herramientas, informe
docker compose --env-file .env.docker logs -f api

# Runner: creación y fin de workers
docker compose --env-file .env.docker logs -f sandbox-runner

# Últimas 200 líneas, sin seguir
docker compose --env-file .env.docker logs --tail 200 api
```

Dentro de un análisis verás, en orden:

```
investigation.start id=inv_… sample=factura.pdf type=pdf size=1390 sha256=…
Crew Execution Started
  Task Started · Agent: Supervisor de análisis de malware
  Tool: analysis_capabilities
  Tool: run_analysis → pdfid, yara, pdf_parser
crew.tool.start / crew.tool.end
crew.plan route=pdf tools=pdfid,yara,pdf_parser gaps=…
  Agent: Analista PDF · Agent: Analista Office · Agent: Analista JavaScript
crew.family family=pdf observations=… concerns=… confidence=…
  Agent: Validador de evidencia
crew.validation consistent=… contradictions=… unsupported=…
  Agent: Redactor de informes técnicos
crew.narrative summary='…' recommendations=… adjustment=…
crew.run.end status=ok tokens=… duration_ms=…
investigation.end verdict=… confidence=… evidence=… iocs=… crew=… tokens=…
```

Con `CREW_VERBOSE=true` (por defecto) además se ven los paneles de CrewAI: **Crew/Task/Agent
Started**, herramientas ejecutadas con sus argumentos y resultados, y **Final Answer** de cada
agente. Es la traza que se ve en la consola de CrewAI, pero dentro de `docker compose logs`.

Ejemplo real (recortado):

```
api-1 | ╭──────────────── 🚀 Crew Execution Started ────────────────╮
api-1 | │  Name: crew                                                  │
api-1 | ╰──────────────────────────────────────────────────────────────╯
api-1 | ╭──────────────── 📋 Task Started ─────────────────────────────╮
api-1 | │  Name: Muestra: factura.pdf · tipo=pdf · 1390 bytes · …       │
api-1 | ╰──────────────────────────────────────────────────────────────╯
api-1 | ╭──────────────── 🤖 Agent Started ────────────────────────────╮
api-1 | │  Agent: Supervisor de análisis de malware                    │
api-1 | ╰──────────────────────────────────────────────────────────────╯
api-1 | ╭──────────────── 🔧 Tool Execution Started (#1) ──────────────╮
api-1 | │  Tool: run_analysis                                          │
api-1 | │  Args: {'tool_id': 'pdfid', 'reason': 'Triaje estructural…'}  │
api-1 | ╰──────────────────────────────────────────────────────────────╯
api-1 | 2026-… INFO argos.crew crew.plan route=pdf tools=pdfid,yara,pdf_parser …
api-1 | 2026-… INFO argos.pipeline investigation.end verdict=malicious …
```

## 2. Niveles y ruido

- `LOG_LEVEL=INFO` (por defecto). `DEBUG` añade detalle de librerías; `WARNING` deja solo avisos.
- El **healthcheck** de Docker (`GET /health` cada 5 s) y los sondeos `httpx` al runner están
  filtrados: no ensucian el log.
- Los avisos de CrewAI sobre conteo aproximado de tokens también se filtran.
- `CREW_VERBOSE=false` desactiva los paneles de CrewAI; quedan las líneas `argos.*` (plan,
  herramientas, validación, narrativa), mucho más compactas.

```dotenv
CREW_VERBOSE=true   # consola rica de CrewAI + líneas argos.*
CREW_VERBOSE=false  # solo líneas argos.*
```

Tras cambiarlo:

```powershell
docker compose --env-file .env.docker up -d --force-recreate api
```

## 3. Qué contienen los logs (privacidad)

| Se registra | No se registra |
| --- | --- |
| Nombre/tipo/tamaño/SHA-256 de la muestra | Bytes del archivo |
| Argumentos y resultados de herramientas | Código completo del malware |
| Plan, hallazgos familiares, validación y resumen | Claves de API ni tokens |
| IOCs defanged y rutas internas del contenedor | Datos personales del analista |

Los logs son **metadatos de evidencia**, no la muestra. Aun así, pueden contener IOCs y
descripciones: trátalos como material sensible y no los compartas fuera del laboratorio.
`docker compose logs` los guarda en el disco de Docker hasta que se roten o se borre el contenedor.

## 4. Si no ves la traza de agentes

1. Comprueba que el contenedor tiene la variable:
   `docker compose --env-file .env.docker exec api env | findstr CREW_VERBOSE`
2. Si falta, añádela a `.env.docker` y recrea la API.
3. Recuerda que sin `DEEPSEEK_API_KEY` no hay crew: verás `llm.status=disabled`.
4. Si el crew falla, el log muestra `crew.run.end status=error` y el pipeline degrada al redactor
   único; revisa `errors=` en esa línea.

## 5. Rotación y tamaño

- `docker compose logs` crece con cada análisis. Para una sesión larga:
  `docker compose --env-file .env.docker logs --tail 500 api > reports\out\api.log`.
- En producción, configura el driver `json-file` con `max-size`/`max-file` en el daemon de Docker.
- `reports/out/` está fuera de git; los logs exportados tampoco deben versionarse.
