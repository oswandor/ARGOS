# ARGOS — Integración con DeepSeek

Todo lo que toca al modelo. Objetivo: que ARGOS sea nativo de DeepSeek sin quedar cautivo, y que
el LLM nunca vea la muestra.

## 1. Por qué DeepSeek

| Requisito | Capacidad |
| --- | --- |
| Muchas llamadas pequeñas | `deepseek-flash` barato y rápido |
| Contexto grande (evidencia + informe) | 1M tokens |
| Tool calling para el supervisor | Formato OpenAI, llamadas en paralelo |
| Salidas parseables | JSON Output y function calling |
| Razonamiento difícil | `deepseek-v4-pro` (thinking) |
| Operación local | API OpenAI-compatible (`base_url`) |

## 2. Endpoint y modelos

| Dato | Valor |
| --- | --- |
| Base URL | `https://api.deepseek.com` (compatible OpenAI) |
| Modelo rápido | `deepseek-flash` |
| Modelo profundo | `deepseek-v4-pro` |
| Alias sin thinking | `deepseek-chat` (**usado por CrewAI**) |
| Contexto | 1M tokens |
| Salida máxima | 384K tokens |

Los nombres y precios cambian: confirma en <https://api-docs.deepseek.com/> antes de fijar
volumen. El modelo se configura por entorno (`MODEL_FAST`, `MODEL_DEEP`, `CREW_MODEL`).

## 3. Dónde se usa

| Punto | Archivo | Modelo |
| --- | --- | --- |
| Agentes CrewAI (supervisor, especialistas, validador, redactor) | `agents/crew.py` | `CREW_MODEL` (`deepseek-chat`) |
| Redactor único de respaldo | `core/llm.py` | `MODEL_FAST` (`deepseek-flash`) |
| Prueba de humo | `scripts/ping_deepseek.py`, `scripts/ping_crew.py` | configurable |

**Una investigación típica con crew hace 6 llamadas** (una por agente). Sin crew, una sola.

## 4. Integración en código

### 4.1 Redactor único (`core/llm.py`)

```python
client = OpenAI(api_key=..., base_url=..., timeout=..., max_retries=1)
response = client.chat.completions.create(
    model=settings.model_fast,
    messages=[...],
    response_format={"type": "json_object"},
    max_tokens=2500,
)
```

- `max_tokens=2500` porque los modelos con *thinking* consumen razonamiento del mismo presupuesto;
  con 512 la respuesta llegaba vacía.
- JSON validado con Pydantic; si falla, se descarta y se usa la plantilla.

### 4.2 Agentes (`agents/crew.py`)

```python
LLM(
    model=f"deepseek/{settings.crew_model}",
    api_key=settings.deepseek_api_key,
    base_url=f"{settings.deepseek_base_url}/v1",
    temperature=0.1,
    max_tokens=2500,
)
```

- CrewAI 1.15 resuelve el proveedor `deepseek/...` de forma nativa (no necesita LiteLLM).
- **No se usa `thinking` como parámetro**: CrewAI lo pasa a `Completions.create` y el SDK lo
  rechaza (`unexpected keyword argument`). Por eso el crew usa `deepseek-chat` (sin thinking).
- Herramientas: `analysis_capabilities` y `run_analysis`, que llaman al `Tool Registry` y este al
  sandbox. El LLM no ejecuta nada directamente.

## 5. Privacidad: qué viaja al proveedor

**Regla dura: al LLM no le llegan bytes de la muestra, rutas locales ni secretos.**

| Se envía | No se envía |
| --- | --- |
| Hashes, tipo, tamaño, entropía | Archivo o base64 |
| Nombres de objetos PDF y categorías | El PDF completo |
| Descripciones de hallazgos y scores | Código completo (solo fragmentos acotados en `preview`) |
| URLs **defanged** | URLs vivas |
| Nombres de APIs y trazas resumidas | Volcados de memoria |
| Cobertura y limitaciones | Claves, rutas de usuario, nombres de máquina |

`core/sanitizer.py` aplica defanging, redacción de rutas/secretos y truncado. `STRICT_PRIVACY=true`
mantiene el modo conservador. El bundle se registra para auditoría.

## 6. Prompt injection desde el malware

1. La evidencia va delimitada y etiquetada como **dato no confiable**.
2. El LLM no tiene capacidad de acción: solo emite JSON validado.
3. El backend vuelve a validar allowlist, tipo y presupuesto en cada `run_analysis`.
4. Toda afirmación debe apoyarse en evidencia; el validador marca las que no.
5. Límite de llamadas por agente y por investigación.

## 7. Costes

- Presupuesto por investigación (`MAX_TOKENS_PER_INVESTIGATION`) y tope de herramientas del crew.
- Crew medido en un PDF sintético: **~58 000–65 000 tokens, ~40 s, 6 llamadas**.
- Redactor único: **~3 000 tokens, ~7 s**.
- `CREW_ENABLED=false` reduce el coste ~20× a cambio de perder el debate multiagente.
- El precio cambia: mide siempre con `usage` (el informe guarda `llm.tokens` y `crew.tokens`).

## 8. Resiliencia

| Fallo | Respuesta |
| --- | --- |
| Sin clave / `ENABLE_LLM=false` | `llm.status=disabled`, informe determinista |
| 429 / 5xx | reintentos con backoff en el cliente |
| Timeout | se corta el paso; el pipeline continúa |
| JSON inválido | se descarta; fallback a redactor único o plantilla |
| Crew falla | reintento de fase 2 → redactor único → plantilla |
| Runner/herramienta caída | `unavailable` en cobertura, el informe lo declara |

## 9. Verificación en vivo (2026-11-15)

| Prueba | Resultado |
| --- | --- |
| Modelos visibles | `deepseek-flash`, `deepseek-v4-pro` |
| Tool calling | `lookup_hash` con argumentos válidos |
| JSON Output | parseado y validado |
| Latencia | 1.4–1.7 s (`flash`), 3.9 s (`v4-pro`) |
| Coste de la prueba | 588 tokens entrada + 1 123 salida ≈ 0.010 CNY |
| Investigación con crew | `crew.status=ok`, 6 agentes, ~58k tokens, ~40 s |
| Ajuste de confianza | 0.93 → 0.90 tras validación |

**Hallazgo clave:** los modelos actuales usan *thinking* por defecto. En prompts largos el
razonamiento consume el presupuesto y el contenido llega vacío. Solución: `deepseek-chat` para el
crew y `max_tokens` amplio en el redactor único.

## 10. DeepSeek Harness como herramienta de desarrollo

DSH se usa solo en el taller, no en producción:

- Probar el contrato de los adaptadores y revisar informes.
- Explorar prompts antes de fijarlos en `agents/crew.py`.

La plataforma no depende de DSH: la orquestación es CrewAI dentro de la API.
