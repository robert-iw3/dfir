#!/bin/sh
# Reconcile the controller's worker registry to exactly the worker that should be there.
#
# Run inside the controller container:  boundary_workers.sh [expected-worker-name]
# Exits non-zero when the expected worker is not registered.
#
# WHY THIS IS ITS OWN GATE. A target with no worker is authorized normally — the controller mints
# a session and hands back a token — and the connection then hangs with nothing to carry it. The
# failure looks like a network problem at the far end of the path, several tiers from the worker
# that never registered.
#
# WHY IT DELETES. A worker's registration outlives the process: rename it, move it to another
# tier, or replace it, and the old row stays, still advertising an address nothing serves. The
# controller hands sessions to workers it believes are registered, so a stale row makes some
# fraction of sessions hang while the rest work — the hardest shape of failure to read. Like the
# grants in boundary_bootstrap.sh, this converges on the intended set rather than accumulating.
set -eu

# All expected worker names, as arguments. The registry converges on exactly this set: a
# stale extra row hands sessions to an address nothing serves, and a missing one caps how many
# workers spread connection setup.
EXPECT="${*:-${BOUNDARY_EGRESS_WORKER_NAME:-ir-egress}}"
: "${BOUNDARY_RECOVERY_KEY:?BOUNDARY_RECOVERY_KEY is required}"
export BOUNDARY_ADDR="${BOUNDARY_ADDR:-https://127.0.0.1:9200}"
export BOUNDARY_CACERT="${BOUNDARY_CACERT:-/boundary/certs/boundary.crt}"

RECOVERY="$(mktemp)"
trap 'rm -f "${RECOVERY}"' EXIT
cat > "${RECOVERY}" <<EOF
kms "aead" {
  purpose   = "recovery"
  aead_type = "aes-gcm"
  key       = "${BOUNDARY_RECOVERY_KEY}"
  key_id    = "global_recovery"
}
EOF

b() { boundary "$@" -recovery-config "${RECOVERY}" -format json; }

# Worker ids carry a `w_` prefix, which is what makes them safe to pull out of the raw response.
# The image has no jq, and a bare "name" match also takes the scope's name nested inside every
# item, so an empty registry reads as a registered worker.
ids() { grep -o '"id":"w_[^"]*"' | cut -d'"' -f4; }

all="$(b workers list -scope-id global 2>&1)" || { echo "${all}" >&2; exit 2; }

keep=""
missing=""
for name in ${EXPECT}; do
    id="$(b workers list -scope-id global \
        -filter "\"/item/name\"==\"${name}\"" 2>/dev/null | ids | head -1)"
    if [ -n "${id}" ]; then
        keep="${keep} ${id}"
        echo "${name} (${id})"
    else
        missing="${missing} ${name}"
    fi
done

for w in $(printf '%s' "${all}" | ids); do
    case " ${keep} " in *" ${w} "*) continue ;; esac
    if b workers delete -id "${w}" >/dev/null 2>&1; then
        echo "removed stale worker registration ${w}"
    else
        echo "could not remove stale worker registration ${w}" >&2
    fi
done

[ -z "${missing}" ] || { echo "worker(s) not registered:${missing}" >&2; exit 1; }
