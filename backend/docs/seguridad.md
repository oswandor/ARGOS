# ARGOS — Seguridad del laboratorio

Este documento trata de **la seguridad de ARGOS**, no del análisis: la plataforma manipula
malware, por lo que es un objetivo legítimo.

## 1. Modelo de amenazas

| Amenaza | Vector | Impacto | Control |
| --- | --- | --- | --- |
| Escape de contenedor | Exploit en parser PDF/Office/box-js | Crítico | Sin red, no-root, rootfs RO, cap-drop ALL, kernel actualizado |
| Infección del host | Abrir la muestra a mano | Crítico | Muestras solo en volumen Docker; no se sirven por HTTP; VM para detonación |
| Exfiltración al LLM | Enviar código o la muestra | Alto | Sanitizador obligatorio, `STRICT_PRIVACY`, solo hechos |
| Prompt injection del malware | Texto que instruye al modelo | Alto | Evidencia delimitada, sin capacidad de acción, JSON validado |
| Abuso de la API | Subidas masivas o anónimas | Medio | `API_KEY` opcional, bind 127.0.0.1, límite de tamaño, dedupe |
| Fuga de secretos | `.env.docker` en git o logs | Alto | `.gitignore`, variables de entorno, rotación |
| Compromiso del runner | Token robado / acceso a 8081 | Alto | No publicado, token compartido, allowlist de imagen↔herramienta |
| Cadena de suministro | Dependencias pip/npm | Alto | Versiones fijadas; pin de imágenes por digest recomendado |
| DoS por muestra | ZIP bomb, PDF recursivo, JS infinito | Medio | Timeouts, profundidad, tamaño, CPU/RAM/PIDs por worker |
| Detonación que toca la red real | VM mal configurada | Crítico | Fuera de alcance actual; requiere hipervisor separado y red simulada |

## 2. Zonas y controles

### Zona de control (`api`)
- Escucha solo en `127.0.0.1` (`ARGOS_API_PORT`); no se publica a la red local.
- **Sin socket Docker**: no puede crear contenedores ni escapar del pipeline.
- Usuario no-root dentro de la imagen (`uid 10000`).
- Acceso a PostgreSQL por la red interna de Compose; el puerto no se publica.
- Secretos por entorno (`.env.docker`), nunca en la imagen ni en el repositorio.
- `API_KEY` opcional: si se define, las rutas de datos exigen `X-API-Key`.

### Zona de sandbox (`sandbox-runner`)
- Único servicio con `/var/run/docker.sock`; no está publicado al host.
- Exige `X-ARGOS-Runner-Token` (comparación en tiempo constante).
- Allowlist fija de parejas `imagen ↔ herramienta`; rechaza cualquier otra.
- Limita tamaño de petición (50 MB), resultado (1 MB) y artefactos.
- Crea volúmenes efímeros con etiqueta `argos.ephemeral` y los borra siempre.
- Si el runner cae, las herramientas se reportan `unavailable`; no se degrada a in-process.

### Zona de análisis (workers)
Checklist que aplica el runner a cada contenedor:

| Control | Valor |
| --- | --- |
| Red | `none` |
| Rootfs | `read_only=True` |
| Capabilities | `cap_drop=["ALL"]` |
| Escalada | `no-new-privileges:true` |
| Usuario | `10001:10001` |
| PIDs / RAM / CPU | 128 / 768 MB / 1 CPU |
| FDs | `nofile=256` |
| `/tmp` | tmpfs `rw,noexec,nosuid,size=64m` |
| Montajes | `/work:ro` y `/out:rw` |
| Socket Docker | **nunca** |

Los artefactos de `/out` se tratan como no confiables y se validan (nombre plano, tamaño máximo).

### Detonación real (futura)
- Hipervisor **distinto** del host de trabajo.
- VM desechable con snapshot y reversión verificada.
- Red simulada (INetSim), sin NAT a Internet ni a la red corporativa.
- Aprobación humana registrada antes de detonar.

## 3. Ciclo de vida de la muestra

```
subida → validación → hash → volumen argos_data (/data/blobs) → análisis
       → artefactos derivados en el mismo volumen
       → informe en ./reports
       → borrado con: .\docker\down.ps1 -DeleteData
```

- La API **no** sirve el binario: solo metadatos e informe.
- No hay retención automática ni Object Lock: el operador decide cuándo borrar el volumen.
- Artefactos (JS extraído, macros, archivos de box-js) pueden contener código: se tratan igual que
  la muestra.

## 4. Secretos y credenciales

| Secreto | Uso | Rotación |
| --- | --- | --- |
| `DEEPSEEK_API_KEY` | LLM y agentes | 90 días o ante sospecha |
| `RUNNER_SHARED_TOKEN` | API ↔ runner | 90 días o al cambiar de host |
| `POSTGRES_PASSWORD` | PostgreSQL local | 180 días |
| `API_KEY` | autenticación de la API | 90 días |
| `VIRUS_TOTAL_API_KEY` | threat intel externo (no activo) | 90 días |

- `.env.docker` está en `.gitignore`; la plantilla pública es `.env.docker.example` sin valores.
- Si una clave se pega en un chat o en un ticket, **revócala** y genera otra.
- No se envían claves al LLM: el sanitizador elimina cadenas con forma de secreto.

## 5. Cumplimiento y ética

- Analizar únicamente muestras propias, de laboratorio o de fuentes públicas destinadas al análisis,
  **sin redistribuirlas**.
- No contactar la infraestructura del atacante: las consultas de reputación son sobre IOCs, no
  visitas a la URL.
- Los informes no incluyen datos personales de terceros; las cadenas extraídas se filtran.
- Si el laboratorio se usa para terceros, se requiere autorización escrita y acuerdo de manejo de
  datos.
- No ofrecer la plataforma como servicio público sin revisión legal.

## 6. Respuesta a incidentes

1. **Aislar**: `.\docker\down.ps1` (conserva datos) o desconectar el host de la red.
2. **Contener**: revocar `DEEPSEEK_API_KEY` y `RUNNER_SHARED_TOKEN`; parar la pila.
3. **Evaluar**: `docker compose logs`, tabla `tool_runs`, tráfico del host, procesos.
4. **Erradicar**: reconstruir el host si hubo ejecución; rotar todos los secretos; recrear volúmenes.
5. **Aprender**: añadir el caso a `tests/regression/` y actualizar este documento.

Un incidente en el laboratorio es un fallo del laboratorio, no de la muestra: la muestra siempre
"gana" si se le da la oportunidad.
