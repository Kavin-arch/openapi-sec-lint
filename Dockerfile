FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --home-dir /app app
COPY pyproject.toml README.md ./
COPY app ./app
COPY static ./static
COPY examples ./examples
RUN python -m pip install --no-cache-dir . \
    && mkdir -p /app/data \
    && chown -R app:app /app

USER app
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
