FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir \
    "fastapi>=0.115" "uvicorn[standard]>=0.30" "pydantic>=2.9" \
    "pydantic-settings>=2.5" "sqlalchemy>=2.0" "python-multipart>=0.0.9" \
    "jinja2>=3.1" "python-dotenv>=1.0" "httpx>=0.27" "openai>=1.40" \
    "crewai>=1.15" "yara-python>=4.5" "pypdf>=5" "olefile>=0.47" \
    "capstone>=5" "psycopg[binary]>=3.2"
COPY api ./api
COPY agents ./agents
COPY core ./core
COPY graphs ./graphs
COPY tools ./tools
COPY workers ./workers
COPY scripts ./scripts
COPY tests ./tests
RUN useradd -u 10000 -m -s /usr/sbin/nologin argos && mkdir -p /data /app/reports/out && chown -R argos:argos /data /app/reports
USER 10000:10000
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
