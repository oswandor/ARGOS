# Sistema de diseño de ARGOS

ARGOS es una consola web para investigar archivos sospechosos. La interfaz prioriza la evidencia, el estado de la investigación y las acciones del analista.

## Fundamentos

- **Superficies:** fondo carbón verdoso `#101719`, superficie `#182224` y superficie elevada `#202d2e`. Las divisiones usan `#3b4b49`.
- **Texto:** principal `#f0f5ef`, secundario `#c0d0c9` y metadatos `#adbfba`.
- **Accento:** lima suave `#d0e897` para acciones principales, foco e iconos funcionales. Los estados de error usan tonos cálidos, siempre acompañados de texto.
- **Tipografía:** Segoe UI con alternativas del sistema. Texto general de 16 px; metadatos y etiquetas de 12–14 px; títulos de página entre 28 y 36 px. Los hashes y registros usan tipografía monoespaciada.
- **Espaciado:** escala base de 4 px, con agrupación cercana y separación generosa entre secciones. Los controles principales tienen al menos 44 px de alto.

## Componentes

- **Navegación:** barra lateral en escritorio y navegación horizontal desplazable en móvil; el destino activo se identifica con texto y fondo.
- **Acciones:** un botón principal por tarea; acciones secundarias con borde, sin sombras decorativas.
- **Estados:** etiquetas con texto y marcador, manteniendo diferencias para errores, análisis activo y finalización.
- **Datos:** tablas alineadas con separación horizontal; desplazamiento cuando no caben en la pantalla.
- **Investigación:** carga y opciones agrupadas, detalle de muestra, eventos en vivo y formatos de informe disponibles sin ocultar funcionalidades.
- **Errores y vacío:** mensajes legibles que identifican el problema; el estado de conexión ofrece reintento.

## Adaptación y accesibilidad

La interfaz conserva las mismas funciones en escritorio, tablet y móvil. Los controles disponen de foco visible; el texto y los elementos se ajustan a nombres largos. Se respeta la preferencia de movimiento reducido. Las comprobaciones automáticas no sustituyen pruebas con tecnologías de asistencia ni dispositivos físicos.
