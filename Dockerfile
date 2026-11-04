FROM python:3.12.16-slim-bookworm@sha256:6dd8b6dab6b3adc7812bab69eca5dbdc1a5cc690ad28306d234ffb4ef8ac9753

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --home-dir /app app
COPY pyproject.toml README.md LICENSE ./
COPY api_checker ./api_checker
RUN python -m pip install --no-cache-dir . \
    && mkdir -p /app/data \
    && chown -R app:app /app

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD-SHELL python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1
CMD ["python", "-m", "uvicorn", "api_checker.main:app", "--host", "0.0.0.0", "--port", "8000"]
