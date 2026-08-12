#!/usr/bin/env bash
# Unseal Vault. Idempotent: does nothing if it is already unsealed.
#
# WHY THIS IS SEPARATE FROM SETUP. Vault seals itself on every restart — that is the design, not
# a fault.
#
# THE SEAL TRADEOFF, stated rather than implied. HashiCorp recommends auto-unseal, which
# requires a KMS or HSM to hold the key.
#
#   IR_VAULT_AUTO_UNSEAL=1  (default)  the unseal key is stored on the vault-state volume and
#                                      applied automatically. Convenient, and correct for
#                                      single-host validation; the key sits at rest in the
#                                      enclave beside the data it protects.
#   IR_VAULT_AUTO_UNSEAL=0             nothing is stored. An operator unseals, and deployment
#                                      waits. Correct for production; requires a human.
#
# Keys are fed on STDIN, never as arguments — an argument is visible in the process list and in
# shell history, which is how unseal keys leak on shared hosts.
set -euo pipefail

STATE=/vault/state
export VAULT_ADDR="${VAULT_ADDR:-https://127.0.0.1:8200}"
export VAULT_CACERT="${VAULT_CACERT:-/certs/vault-ca.crt.pem}"
AUTO="${IR_VAULT_AUTO_UNSEAL:-1}"

# `vault status` exits 2 when SEALED and 1 on error — non-zero is the normal case here, not a
# failure. Captured first, then substituted only if genuinely empty: `cmd || echo '{}'` appends
# the fallback AFTER the JSON the command already printed, and the concatenation does not parse.
status() {
    local o
    o="$(vault status -format=json 2>/dev/null || true)"
    [ -n "${o}" ] && printf '%s' "${o}" || printf '{}'
}
field()  { status | python3 -c "import json,sys
try: print(str(json.load(sys.stdin).get('$1','unknown')).lower())
except Exception: print('unknown')"; }

for i in $(seq 1 60); do
    [ "$(field initialized)" != "unknown" ] && break
    [ "$i" = 60 ] && { echo "vault-unseal: API never answered at ${VAULT_ADDR}" >&2; exit 1; }
    sleep 2
done

if [ "$(field initialized)" != "true" ]; then
    echo "vault-unseal: not initialized — vault-setup-ir.sh runs first" >&2
    exit 2
fi

if [ "$(field sealed)" = "false" ]; then
    echo "vault-unseal: already unsealed"
    exit 0
fi

if [ "${AUTO}" != "1" ]; then
    echo "vault-unseal: SEALED, and auto-unseal is off (IR_VAULT_AUTO_UNSEAL=0)." >&2
    echo "vault-unseal: an operator must unseal before the app tier can start:" >&2
    echo "vault-unseal:   podman exec -it ir-enclave_vault_1 vault operator unseal" >&2
    exit 3
fi

[ -s "${STATE}/vault-init.json" ] || {
    echo "vault-unseal: no unseal material at ${STATE}/vault-init.json" >&2
    echo "vault-unseal: Vault is initialized, so this deployment cannot unseal it — the key was" >&2
    echo "vault-unseal: lost with the volume. The data is unrecoverable without it." >&2
    exit 4
}

# Through the sys/unseal API, not the CLI. `vault operator unseal` offers exactly two ways to
# take the key — as an argument (visible in the process list) or from a TTY prompt (absent
# here); a piped `-` is treated as the literal key.
python3 - "${STATE}/vault-init.json" "${VAULT_ADDR}" "${VAULT_CACERT}" <<'PY'
import json, ssl, sys, urllib.request

init, addr, cacert = sys.argv[1], sys.argv[2], sys.argv[3]
keys = json.load(open(init))["unseal_keys_b64"]
ctx = ssl.create_default_context(cafile=cacert)

for key in keys:
    req = urllib.request.Request(
        f"{addr}/v1/sys/unseal", method="PUT",
        data=json.dumps({"key": key}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        if not json.load(r).get("sealed", True):
            print("vault-unseal: unsealed")
            sys.exit(0)

print(f"vault-unseal: still sealed after applying {len(keys)} key(s)", file=sys.stderr)
sys.exit(1)
PY
