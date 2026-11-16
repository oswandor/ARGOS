# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Analistas de ciberseguridad que investigan archivos sospechosos y necesitan comprender los hallazgos antes de tomar decisiones.

## Product Purpose

ARGOS ayuda a investigar muestras potencialmente maliciosas y prioriza investigaciones explicables: evidencia, limitaciones e informes que apoyan decisiones humanas.

## Positioning

Combina herramientas de análisis de archivos con un flujo de investigación y agentes de IA opcionales; el veredicto procede de la evaluación determinista de la evidencia, no de una decisión autónoma del modelo.

## Operating Context

El analista carga una muestra, configura el análisis, sigue la actividad, consulta los hallazgos y obtiene un informe. También puede buscar indicadores y revisar la disponibilidad de herramientas y servicios.

## Capabilities and Constraints

- Analiza PDF, Office, JavaScript y binarios mediante herramientas aisladas; muestra artefactos y relaciones entre muestras.
- Presenta eventos, resultados, indicadores y reportes JSON, Markdown y HTML.
- Permite configurar espera, LLM, CrewAI y privacidad por investigación.
- El análisis es principalmente estático o emulado: no afirmar que detona malware en una máquina virtual ni que garantiza detección.
- Debe distinguir hechos observados, inferencias y limitaciones, y comunicar cuando un servicio o herramienta no está disponible.
- La aplicación web consume la API existente; no modificar contratos ni lógica de negocio para cambios de diseño.

## Brand Commitments

El producto se llama ARGOS. La interfaz está en español. Su usuario solicitó una interfaz empresarial moderna con identidad propia, evitando patrones genéricos, gradientes excesivos, sombras pronunciadas y tarjetas anidadas innecesarias.

## Evidence on Hand

- La implementación y documentación del backend describen el flujo y sus límites en `../backend/README.md` y `../backend/docs/arquitectura.md`.
- No inventar clientes, certificaciones, resultados de detección ni garantías de seguridad.

## Product Principles

1. Priorizar evidencia y trazabilidad sobre afirmaciones de certeza.
2. Mostrar estado, errores y limitaciones de forma comprensible.
3. Mantener al analista en control de las opciones y decisiones.
4. Proteger el contenido de las muestras y comunicar la configuración de privacidad.
5. Preservar la capacidad de investigar cuando un componente opcional no está disponible.
