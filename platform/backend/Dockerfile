# IR Platform backend (Django API + Celery worker share one image).
FROM docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/venv/bin:$PATH"

# Runtime libs: python + libpq (psycopg C impl) + yara (memory-analysis worker) + curl/bash.
RUN apk add --no-cache python3 py3-pip libpq yara curl bash tzdata

WORKDIR /app
COPY backend/requirements.txt .
# Pure-Python psycopg (loads libpq at runtime) — no C toolchain needed on musl.
RUN python3 -m venv /venv \
    && /venv/bin/pip install --no-cache-dir --upgrade pip \
    && /venv/bin/pip install --no-cache-dir -r requirements.txt

COPY backend/ .
# Single source for the resource statistics every component reports.
COPY shared/sysstats.py ./sysstats.py
RUN chmod +x entrypoint.sh

# Build-time smoke test: every runtime import resolves in the venv before the image ships.
RUN python -c "import django, rest_framework, corsheaders, psycopg, celery, redis, boto3, gunicorn, dateutil; print('backend imports OK')"

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
CMD ["web"]
