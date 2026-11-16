FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.30" "docker>=7.1" "pydantic>=2.9"
COPY runner /app/runner
EXPOSE 8081
CMD ["python", "-m", "uvicorn", "runner.main:app", "--host", "0.0.0.0", "--port", "8081"]
