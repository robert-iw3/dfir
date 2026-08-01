#!/usr/bin/env bash
# Mediator: stage one host's carved regions for a reverse-engineering session.
#
# The RE workstation never reaches the object store and holds no credentials. This runs
# separately, with object-store access, pulls exactly the regions for one host, and leaves
# them in a directory that is mounted read-only into the session.
#
# One host per session. Carved regions live in a bucket per host so a session can be given
# exactly one investigation's malware and nothing else.
#
#   ./stage_regions.sh --host WS-007 --out ./session
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
BE="${IR_BACKEND_CONTAINER:-ir-enclave_backend_1}"
HOSTNAME_ARG=""
OUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOSTNAME_ARG="$2"; shift 2 ;;
        --out)  OUT="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[[ -n "${HOSTNAME_ARG}" ]] || { echo "--host is required" >&2; exit 2; }
OUT="${OUT:-${HERE}/session-${HOSTNAME_ARG}}"

mkdir -p "${OUT}"
# Refuse to mix hosts in one session directory: a session must never hold two
# investigations' malware.
if [[ -f "${OUT}/.host" ]] && [[ "$(cat "${OUT}/.host")" != "${HOSTNAME_ARG}" ]]; then
    echo "refusing: ${OUT} already staged for $(cat "${OUT}/.host")" >&2
    exit 1
fi
echo "${HOSTNAME_ARG}" > "${OUT}/.host"

echo "[stage] pulling carved regions for ${HOSTNAME_ARG}"
# -i is required: without it podman does not forward stdin, so the here-document below
# never reaches python. The file then came out empty and the script failed further down
# with a JSON decode error that said nothing about the actual cause.
${RUNTIME} exec -i -w /app -e PYTHONPATH=/app "${BE}" python - "${HOSTNAME_ARG}" <<'PY' > "${OUT}/_regions.json"
import json, os, sys, base64
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from cases import storage

host = sys.argv[1]
out = []
for obj in storage.list_carved_regions(host):
    local = "/tmp/_stage_" + os.path.basename(obj["key"])
    storage.download_carved_region(host, obj["key"], local)
    with open(local, "rb") as fh:
        out.append({"key": obj["key"], "size": obj["size"],
                    "b64": base64.b64encode(fh.read()).decode()})
    os.remove(local)
print(json.dumps({"host": host, "regions": out}))
PY

# An empty or unparseable file here means the enclave-side step failed, not that the host
# has no regions. Say which, rather than letting a JSON traceback stand in for a diagnosis.
if [[ ! -s "${OUT}/_regions.json" ]]; then
    echo "[stage] the enclave produced no output — is ${BE} running?" >&2
    exit 1
fi

python3 - "${OUT}" <<'PY'
import base64, json, os, sys
out = sys.argv[1]
path = os.path.join(out, "_regions.json")
try:
    doc = json.load(open(path))
except ValueError:
    sys.exit(f"[stage] {path} is not valid JSON — the enclave-side step failed; "
             f"its output is in that file")
n = 0
for r in doc["regions"]:
    dest = os.path.join(out, os.path.basename(r["key"]))
    with open(dest, "wb") as fh:
        fh.write(base64.b64decode(r["b64"]))
    os.chmod(dest, 0o400)   # the session reads them; nothing writes back
    n += 1
# The manifest keeps the object keys without the payload, so the session has provenance
# for each region without any path back to the store.
json.dump({"host": doc["host"],
           "regions": [{"key": r["key"], "size": r["size"]} for r in doc["regions"]]},
          open(os.path.join(out, "_regions.json"), "w"), indent=2)
print(f"[stage] {n} region(s) staged in {out}")
PY
