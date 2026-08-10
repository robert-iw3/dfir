# IR store-and-forward ingest broker. Runs on the connected side.
# Build with the platform/ directory as context so the shared custody module is reachable:
#   podman build -f platform/ingest/Dockerfile -t ir-ingest platform/
FROM docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ENV PYTHONUNBUFFERED=1 PATH="/venv/bin:$PATH"

RUN apk add --no-cache python3 py3-pip ca-certificates \
    && python3 -m venv /venv \
    && /venv/bin/pip install --no-cache-dir --upgrade pip \
    && /venv/bin/pip install --no-cache-dir boto3==1.35.80

WORKDIR /opt/ingest
COPY ingest/ir_ingest.py ./ir_ingest.py
COPY shared/custody.py ./custody.py

# Build-time smoke test: broker + custody imports resolve.
RUN python -c "import boto3, urllib.request, json, hashlib, hmac; print('ingest imports OK')" \
    && python -c "import ast; ast.parse(open('custody.py').read()); ast.parse(open('ir_ingest.py').read()); print('ingest src OK')"

ENTRYPOINT ["python", "ir_ingest.py"]
