#!/usr/bin/env bash
# Enrol the tailnet: create the headscale users the ACL names, mint a pre-auth key per node,
# and write them where compose can read them.
#
# Run by deploy.sh after headscale answers and before the nodes start. It exists because the
# ACL in policy.hujson refers to users by name (`analyst@`, `bastion@`, `operator@`) and those
# users have to exist before a node can join as one — and because a node joins with a key that
# only the control plane can issue, so there is no way to express this in compose alone.
#
# Idempotent: existing users are left alone, and a key is minted only when the node has not
# already joined. Re-running after a node is enrolled is a no-op, so deploy.sh can call it on
# every bring-up without churning node identities.
set -uo pipefail

RUNTIME="${IR_RUNTIME:-podman}"
HS="${IR_HEADSCALE_CONTAINER:-ir-dmz_headscale_1}"
OUT="${1:?usage: tailnet_bootstrap.sh <env-file-to-write>}"

# The users the ACL grants from. Keep in step with policy.hujson: a src that names a user
# which does not exist is a rule that silently never matches.
USERS="analyst bastion operator"

hs() { "${RUNTIME}" exec -i "${HS}" headscale "$@" 2>/dev/null; }

# `preauthkeys create --user` takes a NUMERIC user id, not a name — passing the name is
# accepted on the command line and then matches nothing. The ACL names users, the CLI keys on
# their ids, so the two have to be reconciled here.
user_id() {
    hs users list --output json 2>/dev/null | python3 -c "
import json,sys
want = sys.argv[1]
try: rows = json.load(sys.stdin)
except Exception: sys.exit(0)
for r in rows if isinstance(rows, list) else []:
    if r.get('name') == want:
        print(r.get('id', '')); break
" "$1"
}

hs version >/dev/null 2>&1 || {
    echo "[tailnet] ${HS} is not answering — start the DMZ tier first" >&2; exit 1; }

# --- users -------------------------------------------------------------------
existing="$(hs users list --output json 2>/dev/null || echo '[]')"
for u in ${USERS}; do
    if grep -q "\"name\":\"${u}\"" <<<"${existing//[[:space:]]/}"; then
        echo "[tailnet] user ${u} present"
    else
        hs users create "${u}" >/dev/null && echo "[tailnet] created user ${u}" \
            || echo "[tailnet] WARN: could not create user ${u}" >&2
    fi
done

# --- nodes already joined ----------------------------------------------------
# A node that has joined needs no key. Minting one anyway is harmless but noisy, and reusing
# a stale key in .env after the node is up leads to a second node with the same hostname.
nodes="$(hs nodes list --output json 2>/dev/null || echo '[]')"
joined() { grep -q "\"given_name\":\"$1\"" <<<"${nodes//[[:space:]]/}"; }

# --- keys --------------------------------------------------------------------
# Reusable and short-lived: a bring-up may start a node more than once (compose recreates on
# config change), and a single-use key would fail the second attempt in a way that looks like
# a tunnel fault. The window is what bounds it, not single use.
KEY_TTL="${IR_TAILNET_KEY_TTL:-2h}"

: > "${OUT}"
chmod 600 "${OUT}"
{
    echo "# Written by tailnet_bootstrap.sh — short-lived pre-auth keys, not for committing."
    echo "# TTL ${KEY_TTL} from $(date -u +%Y-%m-%dT%H:%M:%SZ)."
} >> "${OUT}"

mint() { # user  hostname  env-var
    local user="$1" host="$2" var="$3" key
    # A key is ALWAYS minted, even when the control plane already lists this node.
    #
    # Withholding one on the strength of "already enrolled" creates a state nothing can leave:
    # headscale still has the node record, but the node's own credentials no longer work — the
    # state volume was replaced, the key expired, or the control-plane database was rebuilt
    # underneath it. The node then starts with no key, cannot authenticate, and exits; the
    # bootstrap sees it still listed and again declines to issue one. The tunnel is gone and
    # every re-run reproduces the same deadlock.
    #
    # Minting unconditionally costs nothing: the keys are reusable, expire in hours, and a node
    # holding valid state simply never presents one.
    local uid
    uid="$(user_id "${user}")"
    if [[ -z "${uid}" ]]; then
        echo "[tailnet] WARN: user ${user} has no id — cannot mint a key" >&2
        echo "${var}=" >> "${OUT}"
        return 1
    fi
    key="$(hs preauthkeys create --user "${uid}" --reusable --expiration "${KEY_TTL}" \
             2>/dev/null | tr -d '[:space:]')"
    if [[ -z "${key}" ]]; then
        echo "[tailnet] WARN: no pre-auth key issued for ${user}/${host}" >&2
        echo "${var}=" >> "${OUT}"
        return 1
    fi
    echo "${var}=${key}" >> "${OUT}"
    echo "[tailnet] key issued for ${user}/${host}"
}

rc=0
mint bastion  bastion  TS_BASTION_AUTHKEY  || rc=1
mint analyst  analyst  TS_ANALYST_AUTHKEY  || rc=1

echo "[tailnet] wrote ${OUT}"
exit "${rc}"
