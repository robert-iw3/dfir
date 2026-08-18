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
#   ./stage_regions.sh --workset ws-64-ws-007-3        # exactly that workset's regions
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
BE="${IR_BACKEND_CONTAINER:-ir-enclave_backend_1}"
HOSTNAME_ARG=""
OUT=""

WORKSET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)    HOSTNAME_ARG="$2"; shift 2 ;;
        --workset) WORKSET="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[[ -n "${HOSTNAME_ARG}" || -n "${WORKSET}" ]] \
    || { echo "--host or --workset is required" >&2; exit 2; }
[[ -z "${HOSTNAME_ARG}" || -z "${WORKSET}" ]] \
    || { echo "--host and --workset are alternatives, not a pair" >&2; exit 2; }
if [[ -n "${WORKSET}" ]]; then
    # The workset knows which host it is for; asking the enclave keeps that single-sourced
    # rather than making the operator repeat it and risk staging the wrong bucket.
    HOSTNAME_ARG="$(${RUNTIME} exec -i -w /app -e PYTHONPATH=/app "${BE}" python - "${WORKSET}" <<'HOSTPY' 2>/dev/null
import os, sys
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from cases.models import ReWorkset

ws = ReWorkset.objects.filter(slug=sys.argv[1]).select_related("host").first()
print(ws.host.hostname if ws and ws.host else "")
HOSTPY
)"
    HOSTNAME_ARG="$(printf '%s' "${HOSTNAME_ARG}" | tr -d '[:space:]')"
    [[ -n "${HOSTNAME_ARG}" ]] || {
        echo "[stage] no workset ${WORKSET} in the enclave — check the slug" >&2; exit 1; }
fi
OUT="${OUT:-${HERE}/session-${WORKSET:-${HOSTNAME_ARG}}}"

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
${RUNTIME} exec -i -w /app -e PYTHONPATH=/app "${BE}" python - "${HOSTNAME_ARG}" "${WORKSET}" <<'PY' > "${OUT}/_regions.json"
import json, os, sys, base64
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from cases import storage

host, workset = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
if workset:
    # A workset names EXACTLY which regions this session is for, so the pull is that list
    # and not the host's whole bucket — the difference between eighteen regions and four
    # hundred, and the reason the session opens at all.
    from cases.models import ReWorkset
    ws = ReWorkset.objects.filter(slug=workset).first()
    wanted = [{"key": m.region.object_key, "size": m.region.size_bytes,
               "sha256": m.region.sha256}
              for m in ws.members.select_related("region").order_by("rank", "id")] if ws else []
else:
    from cases.models import CarvedRegion
    known = dict(CarvedRegion.objects.filter(
        analysis__capture__run__host__hostname=host).values_list("object_key", "sha256"))
    wanted = [{"key": o["key"], "size": o["size"], "sha256": known.get(o["key"], "")}
              for o in storage.list_carved_regions(host)]

out = []
for obj in wanted:
    local = "/tmp/_stage_" + os.path.basename(obj["key"])
    storage.download_carved_region(host, obj["key"], local)
    with open(local, "rb") as fh:
        out.append({"key": obj["key"], "size": obj["size"],
                    "sha256": obj.get("sha256", ""),
                    "b64": base64.b64encode(fh.read()).decode()})
    os.remove(local)
print(json.dumps({"host": host, "workset": workset, "regions": out}))
PY

# An empty or unparseable file here means the enclave-side step failed, not that the host
# has no regions. Say which, rather than letting a JSON traceback stand in for a diagnosis.
if [[ ! -s "${OUT}/_regions.json" ]]; then
    echo "[stage] the enclave produced no output — is ${BE} running?" >&2
    exit 1
fi

python3 - "${OUT}" <<'PY'
import base64, hashlib, json, os, sys
out = sys.argv[1]
path = os.path.join(out, "_regions.json")
try:
    doc = json.load(open(path))
except ValueError:
    sys.exit(f"[stage] {path} is not valid JSON — the enclave-side step failed; "
             f"its output is in that file")
def local_name(key):
    """A name unique within the session.

    Object keys are {investigation}/{capture}/{name}.bin; basename alone collapsed two
    captures of the same host onto one filename, so the second silently replaced the first
    and a region an analyst was asked to examine was not the one they opened.
    """
    parts = [p for p in key.split("/") if p]
    if len(parts) >= 3:
        return f"{parts[-2]}_{parts[-1]}"
    return os.path.basename(key)

n, bad = 0, []
for r in doc["regions"]:
    dest = os.path.join(out, local_name(r["key"]))
    raw = base64.b64decode(r["b64"])
    # The hash recorded at carve time is checked HERE, against the bytes about to be opened.
    # Recorded and never verified, it says nothing: an analyst would examine whatever
    # arrived and could not tell it apart from what was carved.
    expected = (r.get("sha256") or "").lower()
    actual = hashlib.sha256(raw).hexdigest()
    if expected and actual != expected:
        bad.append(f"{local_name(r['key'])}: carved {expected[:12]}…, staged {actual[:12]}…")
        continue
    with open(dest, "wb") as fh:
        fh.write(raw)
    os.chmod(dest, 0o400)   # the session reads them; nothing writes back
    n += 1
if bad:
    sys.exit("[stage] REFUSED — staged bytes do not match what was carved:\n  "
             + "\n  ".join(bad))
# The manifest keeps the object keys without the payload, so the session has provenance
# for each region without any path back to the store.
json.dump({"host": doc["host"], "workset": doc.get("workset", ""),
           "regions": [{"key": r["key"], "size": r["size"], "sha256": r.get("sha256", ""),
                        "file": local_name(r["key"])} for r in doc["regions"]]},
          open(os.path.join(out, "_regions.json"), "w"), indent=2)
print(f"[stage] {n} region(s) staged in {out}")
PY

# Tell the enclave the session started. Without this the workset stays "assembled" forever
# and the platform cannot say which sessions are open — it hands work out and never learns
# that anyone picked it up. Best-effort: a session that is already staged must not fail
# because the record of it did.
if [[ -n "${WORKSET}" ]]; then
    STAGED_N="$(find "${OUT}" -maxdepth 1 -name '*.bin' 2>/dev/null | wc -l)"
    ${RUNTIME} exec -i -w /app "${BE}" python - "${WORKSET}" "${STAGED_N}" <<'MARK' >/dev/null 2>&1 || \
        echo "[stage] warning: the enclave was not told this workset is staged" >&2
import os, sys
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings")
django.setup()
from django.utils import timezone
from cases import audit as audit_mod
from cases.models import ReWorkset

slug, count = sys.argv[1], sys.argv[2]
ws = ReWorkset.objects.filter(slug=slug).first()
if ws:
    ws.state, ws.staged_at = ReWorkset.STAGED, timezone.now()
    ws.save(update_fields=["state", "staged_at", "updated_at"])
    audit_mod.audit("mediator", "workset.staged", role="service", method="",
                    path="stage_regions.sh", object_type="ReWorkset", object_id=ws.slug,
                    detail={"regions": int(count)}, covers_request=False)
MARK
fi
