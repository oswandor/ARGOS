# ARGOS

El backend se encuentra en `backend/` y la interfaz React en `frontend-argos/`.

Para levantar frontend y backend juntos con Docker Desktop, ejecuta desde la raíz:

```powershell
.\up.ps1
```

La primera ejecución prepara `backend/.env.docker` y construye las imágenes de análisis. La interfaz estará en http://127.0.0.1:5173 y Swagger en http://127.0.0.1:8000/docs. Para reconstruir también los workers usa `.\up.ps1 -ForceBuild`. Detén la pila con `docker compose down`; los datos persistentes se conservan.

El frontend usa Nginx para redirigir `/api` a la API dentro de la red Docker. Si configuras `API_KEY` en `backend/.env.docker`, define además `VITE_API_KEY` en el entorno de Compose antes de construir el frontend; esta clave queda visible en el navegador y solo es apropiada para entornos controlados. Para cambiar el puerto del frontend define `ARGOS_FRONTEND_PORT` en el entorno de Compose.

También puedes iniciar la interfaz para desarrollo con `cd frontend-argos`, copiando `.env.example` a `.env` y ejecutando `npm install` y `npm run dev`.

Consulta la [documentación del backend](backend/README.md) para más detalles.

La interfaz permite elegir si espera el resultado y configurar LLM, CrewAI y privacidad por investigación. La actividad se muestra en el detalle de la muestra. Para clientes API, `GET /investigation-options` devuelve los valores iniciales; `POST /investigations` recibe el archivo y las opciones como formulario, y devuelve el identificador. Después `POST /investigations/{id}/start?wait=false` inicia el análisis. `GET /investigations/{id}` devuelve el estado y `GET /investigations/{id}/events?after=0` permite consultar eventos incrementales usando `next_cursor`.
