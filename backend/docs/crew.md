# ARGOS — Agentes CrewAI

La orquestación multiagente usa **CrewAI 1.15** sobre la API de DeepSeek. Sustituye al
supervisor LangGraph del plan sin cambiar la capa de herramientas: los agentes usan el
mismo `Tool Registry` y el mismo sandbox Docker.

## 1. Flujo en dos fases

```
FASE 1 — planificación y recolección
  Supervisor ──► analysis_capabilities(tipo)
             ──► run_analysis(tool)  ──► Tool Registry ──► Docker worker
             ──► AnalysisPlan {route, tools_used, gaps, rationale}
                        │
                        ▼
  (el backend garantiza evidencia: si el supervisor no ejecutó
   herramientas de contenido, corre el plan determinista de respaldo)

FASE 2 — interpretación y validación
  Analista PDF / Office / JS / Shellcode  (solo familias presentes)
             ──► FamilyFinding
  Validador  ──► ValidationDecision {consistent, contradictions, unsupported_claims}
  Redactor   ──► ReportNarrative {summary, attack_chain, recommendations, ±0.05}
                        │
                        ▼
  Informe JSON/MD/HTML (el veredicto y el riesgo siguen siendo deterministas)
```

La separación existe porque el redactor necesita evidencia que aún no existe cuando se
crean las tareas. Construir una sola crew producía informes sobre evidencia vacía.

## 2. Agentes

| Agente | Herramientas | Salida |
| --- | --- | --- |
| Supervisor | `analysis_capabilities`, `run_analysis` | `AnalysisPlan` |
| Analista PDF | — | `FamilyFinding` |
| Analista Office | — | `FamilyFinding` |
| Analista JavaScript | — | `FamilyFinding` |
| Analista Shellcode | — | `FamilyFinding` |
| Validador | — | `ValidationDecision` |
| Redactor | — | `ReportNarrative` |

Los especialistas se crean **solo si hay evidencia de su familia** en `tool_outputs`.

## 3. Guardarraíles

- **Allowlist real**: `run_analysis` revalida tipo, `ALLOWLIST`, presupuesto y máximo de
  llamadas. `triage` e `intel` están reservadas al backend y se rechazan.
- **Sin shell ni Docker**: el agente solo puede pedir IDs del registro.
- **Veredicto determinista**: el LLM no puede cambiarlo; solo redacta y ajusta la confianza
  ±0.05, que además se recorta en el pipeline.
- **Datos saneados**: `_digest()` solo envía hashes, descripciones, IOCs defanged y
  cobertura; sin bytes, rutas ni código completo.
- **Prompt injection**: la evidencia va delimitada y etiquetada como no confiable.
- **Validación**: si el validador marca contradicciones, se añaden a limitaciones y la
  confianza baja 0.03. Si el JSON no valida, se descarta.
- **Degradación**: cualquier excepción → un reintento de la fase 2 → redactor único
  (`core/llm.py`) → plantilla determinista.

## 4. Modelo: `deepseek-chat`, no `deepseek-flash`

CrewAI usa `deepseek-chat` por defecto (`CREW_MODEL`). Es el alias **sin thinking** del
modelo actual:

- `deepseek-flash` razona por defecto. En prompts largos de agente, el razonamiento se
  comía el presupuesto y la API devolvía contenido vacío
  (`EmptyLLMResponseError: The provider returned no content`).
- `deepseek-chat` responde en ~1.5 s por llamada y no tiene ese problema.
- El redactor único (fallback) sigue usando `deepseek-flash` con `max_tokens=2500`.

No se intenta desactivar thinking con `LLM(additional_params={"thinking": ...})`: CrewAI lo
pasa como kwarg a `Completions.create` y el SDK lo rechaza (`unexpected keyword argument`).

## 5. Coste y latencia medidos

Caso PDF sintético (factura con JS + DOCM embebido), 6 agentes:

| Métrica | Valor |
| --- | --- |
| Tokens | ~58 000–65 000 |
| Duración | ~38–40 s |
| Coste aproximado (chat) | ~0.1–0.2 CNY |
| Llamadas de red | 6 |
| Herramientas ejecutadas por el supervisor | 3 (pdfid, pdf_parser, yara) |

Con `CREW_ENABLED=false` el informe se redacta con una sola llamada (~3 000 tokens, 7 s).

## 6. Configuración

En la pila Compose se configura en `.env.docker`:

```dotenv
CREW_ENABLED=true
CREW_MODEL=deepseek-chat
CREW_MAX_TOOL_CALLS=4
CREW_VERBOSE=true
```

`CREW_VERBOSE=true` muestra en `docker compose logs api` la traza de CrewAI (agente, tarea,
herramientas, Final Answer). Detalle en [logs.md](logs.md).

Tras cambiarlo: `docker compose --env-file .env.docker up -d --force-recreate api`.

Prueba de humo aislada:

```powershell
docker compose --env-file .env.docker exec -T api python scripts/ping_crew.py
```

## 7. Límites

- El plan del supervisor se redacta antes del análisis de artefactos hijos: sus `gaps`
  pueden quedar desactualizados. El validador lo sabe (nota explícita) y la evidencia manda.
- Proceso secuencial: 6 llamadas de red. No hay paralelismo ni memoria entre
  investigaciones todavía.
- El coste en tokens es ~20× el de una sola llamada; por eso `CREW_ENABLED` es configurable.
- Los especialistas interpretan, no generan evidencia nueva: la evidencia viene de las
  herramientas deterministas.
