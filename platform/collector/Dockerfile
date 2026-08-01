# IR Platform Linux collection container.
FROM docker.io/library/alpine:3.24

ENV PYTHONUNBUFFERED=1

# Collection + analysis runtime: python3 (stdlib toolkit), bash/coreutils/procps/iproute2
# (host inspection), yara (file/memory scan), gcompat (run glibc avml on musl).
RUN apk add --no-cache \
        bash coreutils procps iproute2 findutils grep sed gawk \
        python3 yara ca-certificates gcompat \
        curl

# Staged toolkit subtree (assembled into ./toolkit by build.sh).
COPY toolkit /opt/toolkit
RUN chmod +x /opt/toolkit/Invoke-IRCollection-Linux.sh 2>/dev/null || true \
    && chmod +x /opt/toolkit/tools/avml 2>/dev/null || true

# Collector entrypoint + custody + synthetic-sample helper.
COPY collect.sh ship.sh make_sample.py symbol_requisites.py preflight.py custody.py /opt/collector/
RUN chmod +x /opt/collector/collect.sh

# Build-time smoke test: python + bash present, custody module imports, avml staged.
RUN python3 -c "import sys,hashlib,json,os,re,math,struct; print('collector py OK', sys.version.split()[0])" \
    && python3 -c "import ast; ast.parse(open('/opt/collector/custody.py').read()); print('custody OK')" \
    && bash --version >/dev/null \
    && test -x /opt/toolkit/tools/avml

WORKDIR /opt/collector
ENTRYPOINT ["/opt/collector/collect.sh"]
