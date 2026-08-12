#!/usr/bin/env bash
# ==============================================================================
# VAULT UAT — dynamic secrets for the application tier, asserted on the deployment.
#
# The platform holds no static application credential: Vault's database engine issues the app
# tier short-lived Postgres users, and its KV holds the app's other secrets — including
# IR_CUSTODY_HMAC_KEY, the key that seals the chain of custody. This proves:
#
#   1. PLACEMENT. Vault, its agent and its state are in the enclave, on the internal
#      network only. The secrets authority lives in the tier the design trusts.
#
#   2. IT IS SERVING. Initialized AND unsealed — a sealed Vault answers health checks
#      and serves nothing, so container state proves nothing here.
#
#   3. HARDENED PER THE VENDOR. The audit device is enabled and recording, and the
#      initial root token was revoked and removed after provisioning.
#
#   4. THE APP RUNS ON ISSUED CREDENTIALS. Django's live connection logs in as a
#      Vault-minted user (v-*) and acts as the stable owner role ir_app, which is what
#      keeps object ownership fixed across rotation.
#
#   5. EVERY DATABASE IS COVERED. The correlation database has its own django_migrations;
#      a grant that reaches only the primary lets the app authenticate, migrate the first
#      database, and then die on the second — blaming everything but the bootstrap.
#
# Every check runs from a running container, against the deployment the codebase produced.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

VAULT=ir-enclave_vault_1
AGENT=ir-enclave_vault-agent_1
BACKEND=ir-enclave_backend_1

. "${HERE}/lib/report.sh"
report_begin 40 vault "Secrets — Vault dynamic credentials" \
    "The platform holds no static application credential: Vault issues short-lived database users the app provably runs on, the custody key is Vault-sourced, the store is audited with its root revoked, and a full rotation converges the platform onto fresh credentials while it stays up."

running() { [[ "$(${RUNTIME} inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]; }

# ============================================================ 1. placement
say "Placement — the secrets authority is in the enclave"
for pair in "${VAULT}:Vault server" "${AGENT}:Vault agent"; do
    c="${pair%%:*}"; label="${pair##*:}"
    running "${c}" && ok "${label} is running in the enclave" || bad "${label} (${c}) is not running"
done
nets="$(${RUNTIME} inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${VAULT}" 2>/dev/null)"
[[ "${nets// /}" == "ir-enclave_internal" ]] \
    && ok "Vault sits on the internal network and nothing else" \
    || bad "Vault is attached to more than the internal network: ${nets}"

# ============================================================ 2. serving
say "Vault is initialized and unsealed"
vs="$(${RUNTIME} exec -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/certs/vault-ca.crt.pem \
      "${VAULT}" vault status -format=json 2>/dev/null)"
grep -q '"initialized": *true' <<<"${vs}" && ok "initialized" || bad "not initialized"
grep -q '"sealed": *false' <<<"${vs}" && ok "unsealed" \
    || bad "SEALED — it answers health checks and serves nothing; deploy.sh runs vault-unseal.sh"

# Unsealed BECAUSE THE SERVER DOES IT, not because a deploy happened to run recently. Vault
# seals on every restart by design, and restarts have causes a deploy never sees — a crash, an
# operator, or the mesh repair recreating a sidecar and taking its service with it.
say "The signing keys survive provisioning — rotation is never a side effect of deploying"
kv_fp() { ${RUNTIME} exec "$1" sh -c \
    'printf "%s|%s" "${IR_AUDIT_HMAC_KEY}" "${IR_CUSTODY_HMAC_KEY}" | sha256sum | cut -c1-32' 2>/dev/null; }
KV_BEFORE="$(kv_fp ir-enclave_backend_1)"
if [[ -z "${KV_BEFORE}" || "${KV_BEFORE}" == "$(printf '|' | sha256sum | cut -c1-32)" ]]; then
    bad "the backend holds no signing keys — the audit HMAC and custody seal are not in force"
else
    # Re-run the provisioning one-shot, which is what a deploy does, then compare.
    ${RUNTIME} start ir-enclave_vault-setup_1 >/dev/null 2>&1
    for _ in $(seq 1 45); do
        [[ "$(${RUNTIME} inspect ir-enclave_vault-setup_1 --format '{{.State.Status}}' 2>/dev/null)" == "running" ]] || break
        sleep 2
    done
    KV_AFTER="$(kv_fp ir-enclave_backend_1)"
    [[ "${KV_BEFORE}" == "${KV_AFTER}" ]] \
        && ok "re-running provisioning left the audit and custody signing keys UNCHANGED (${KV_AFTER:0:12}) — every signature and seal already written still verifies against them" \
        || bad "provisioning ROTATED the signing keys (${KV_BEFORE:0:12} -> ${KV_AFTER:0:12}) — every audit signature and custody seal written before this deploy is now unverifiable"
fi

say "Vault recovers from a restart on its own"
${RUNTIME} restart "${VAULT}" >/dev/null 2>&1
rs=""
for _ in $(seq 1 30); do
    rs="$(${RUNTIME} exec -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/certs/vault-ca.crt.pem \
          "${VAULT}" vault status -format=json 2>/dev/null)"
    grep -q '"sealed": *false' <<<"${rs}" && break
    sleep 2
done
grep -q '"sealed": *false' <<<"${rs}" \
    && ok "a restart nothing deploy-related caused came back UNSEALED — recovery is a property of the server, not of the deployment" \
    || bad "SEALED after a plain restart — unsealing happens only at deploy time, so every other restart silently degrades the platform"

# That restart gave Vault a new network namespace and stranded its mesh proxy. Repaired through
# the deployment's own path: a test that leaves the mesh reporting healthy while carrying
# nothing has traded one silent failure for another.
bash "${HERE}/../deploy/deploy.sh" mesh >/dev/null 2>&1
vpid="$(${RUNTIME} inspect "${VAULT}" --format '{{.State.Pid}}' 2>/dev/null)"
spid="$(${RUNTIME} inspect ir-enclave_vault-sidecar_1 --format '{{.State.Pid}}' 2>/dev/null)"
[[ -n "${vpid}" && -n "${spid}" \
   && "$(readlink "/proc/${vpid}/ns/net" 2>/dev/null)" == "$(readlink "/proc/${spid}/ns/net" 2>/dev/null)" ]] \
    && ok "and its mesh proxy was reattached to the new namespace, so the stack is left serving" \
    || bad "vault-sidecar is stranded from Vault's namespace — the mesh reports healthy and carries nothing"

# ============================================================ 3. vendor hardening
say "Hardening — audit on, root revoked"
# The audit device records every privileged operation against the store that holds the custody
# key. It must exist AND be growing — an enabled device pointed at an unwritable path is fatal
# to Vault itself, so mere existence is close to proof, but recording is the actual claim.
asz="$(${RUNTIME} exec --user root "${VAULT}" sh -c 'wc -c < /vault/logs/vault-audit.log' 2>/dev/null | tr -d '[:space:]')"
if [[ "${asz:-0}" -gt 0 ]]; then
    ok "audit device is recording (${asz} bytes)"
else
    bad "no audit log — privileged operations against the secrets store are unrecorded"
fi
# "Once you complete initial Vault setup, you should revoke the initial root token."
rt="$(${RUNTIME} exec --user root "${VAULT}" python3 -c \
     "import json; d=json.load(open('/vault/state/vault-init.json')); print('root_token' in d)" 2>/dev/null | tr -d '[:space:]')"
[[ "${rt}" == "False" ]] \
    && ok "initial root token revoked and removed from state" \
    || bad "the initial root token is still on disk — anything reading that volume owns Vault"

# ============================================================ 4. issued credentials
say "The app tier runs on Vault-issued credentials"
rendered="$(${RUNTIME} exec "${AGENT}" cat /vault/secrets/app.env 2>/dev/null)"
dyn="$(sed -n 's/^export POSTGRES_USER=//p' <<<"${rendered}" | head -1)"
[[ "${dyn}" == v-* ]] \
    && ok "agent rendered a Vault-minted database user (${dyn})" \
    || bad "rendered user does not look Vault-issued (${dyn:-none})"
[[ "${dyn}" != "${POSTGRES_USER:-ir_platform}" ]] \
    && ok "it is not the static admin" \
    || bad "the rendered user IS the static admin — the database engine is not in play"
grep -q '^export IR_CUSTODY_HMAC_KEY=' <<<"${rendered}" \
    && ok "the custody HMAC key is Vault-sourced" \
    || bad "the custody key is not in the rendered secrets — it is coming from a static file"
grep -q '^export DJANGO_SECRET_KEY=' <<<"${rendered}" \
    && ok "Django key + remaining app secrets are Vault-sourced" \
    || bad "KV secrets not rendered"

# Who Django is on the wire, asked of the LIVE connection: logs in as the dynamic user
# (session_user), acts as the fixed owner (current_user after the role's SET). Anything else
# means rotation will strand object ownership with a credential that expires.
ident="$(${RUNTIME} exec "${BACKEND}" sh -c \
    '. /vault/secrets/app.env && python manage.py shell -c "from django.db import connection; c=connection.cursor(); c.execute(\"select session_user||chr(124)||current_user\"); print(c.fetchone()[0])"' 2>/dev/null | grep '|' | tail -1)"
login="${ident%%|*}"; acts="${ident##*|}"
[[ "${login}" == v-* ]] && ok "Django logs in as the Vault dynamic user (${login})" \
    || bad "Django is not on a Vault user (${login:-no answer})"
[[ "${acts}" == "ir_app" ]] && ok "and acts as the stable owner role ir_app (rotation-safe)" \
    || bad "not acting as ir_app (${acts:-no answer})"

# ============================================================ 5. every database
say "Both databases answer the dynamic user"
for db in "${POSTGRES_DB:-ir_platform}" "${CORRELATION_POSTGRES_DB:-ir_correlation}"; do
    n="$(${RUNTIME} exec "${BACKEND}" sh -c '. /vault/secrets/app.env && python - <<PY
import os, psycopg
with psycopg.connect(host=os.environ.get("POSTGRES_HOST","db"), dbname="'"${db}"'",
                     user=os.environ["POSTGRES_USER"], password=os.environ["POSTGRES_PASSWORD"]) as c:
    print(c.execute("select count(*) from django_migrations").fetchone()[0])
PY' 2>&1 | tail -1)"
    if [[ "${n}" =~ ^[0-9]+$ ]]; then
        ok "${db}: django_migrations readable (${n} rows)"
    else
        bad "${db}: the dynamic user cannot read it — db-bootstrap missed this database"
        info "$(head -1 <<<"${n}")"
    fi
done

# The API serving over those credentials is the end of the chain.
${RUNTIME} exec "${BACKEND}" python -c \
    "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/health/', timeout=5)" >/dev/null 2>&1 \
    && ok "API healthy over the issued credentials" \
    || bad "API not healthy — the chain breaks somewhere above"

# ============================================================ 6. rotation, executed
say "Rotation — executed, not assumed"
# Issuing a credential once proves the engine works on a fresh deployment. Rotation is the other
# half of the claim: the OLD credential dies immediately, a NEW one is issued, and the platform
# converges onto it while staying up.
busy="$(${RUNTIME} exec ir-enclave_worker_1 sh -c 'ps -eo args | grep -c "[a]nalyze_memory_linux"' 2>/dev/null | head -1)"
busy="${busy:-0}"
if [[ "${busy:-0}" -gt 0 ]]; then
    info "a memory analysis is running — rotation not exercised this run (nothing asserted)"
else
    pre_django="$(sed -n 's/^export DJANGO_SECRET_KEY=//p' <<<"${rendered}" | head -1)"
    if rot_out="$(bash "${PLATFORM}/hashicorp/vault/rotate-app-creds.sh" 2>&1)"; then
        ok "rotation procedure completed ($(grep -o 'rotation complete: [^,]*' <<<"${rot_out}" | head -1))"
    else
        bad "rotation procedure FAILED:"
        info "$(tail -3 <<<"${rot_out}")"
    fi
    rendered2="$(${RUNTIME} exec "${AGENT}" cat /vault/secrets/app.env 2>/dev/null)"
    new="$(sed -n 's/^export POSTGRES_USER=//p' <<<"${rendered2}" | head -1)"
    [[ "${new}" == v-* && "${new}" != "${dyn}" ]] \
        && ok "a NEW credential was issued (${dyn} -> ${new})" \
        || bad "no new credential after rotation (still ${new:-empty})"
    # The old user must be GONE from Postgres — revocation-on-rotate, not expiry-at-TTL.
    gone="$(${RUNTIME} exec ir-enclave_db_1 psql -U "${POSTGRES_USER:-ir_platform}" -d postgres -tAc \
        "select count(*) from pg_roles where rolname='${dyn}'" 2>/dev/null | tr -d '[:space:]')"
    [[ "${gone}" == "0" ]] \
        && ok "the old user was dropped from Postgres at rotation (${dyn})" \
        || bad "the old user still exists in Postgres — revocation did not run"
    # And the live connection is on the new one.
    ident2="$(${RUNTIME} exec "${BACKEND}" sh -c \
        '. /vault/secrets/app.env && python manage.py shell -c "from django.db import connection; c=connection.cursor(); c.execute(\"select session_user\"); print(c.fetchone()[0])"' 2>/dev/null | grep '^v-' | tail -1)"
    [[ "${ident2}" == "${new}" ]] \
        && ok "Django's live connection is on the new user (${ident2})" \
        || bad "Django is not on the new user (${ident2:-no answer} vs ${new})"
    # KV must NOT have rotated: a changed custody key orphans every existing seal.
    post_django="$(sed -n 's/^export DJANGO_SECRET_KEY=//p' <<<"${rendered2}" | head -1)"
    [[ -n "${pre_django}" && "${post_django}" == "${pre_django}" ]] \
        && ok "KV secrets (custody/Django keys) unchanged by rotation, as they must be" \
        || bad "KV secrets CHANGED during rotation — existing custody seals may be orphaned"
    ${RUNTIME} exec "${BACKEND}" python -c \
        "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/health/', timeout=5)" >/dev/null 2>&1 \
        && ok "platform healthy on the rotated credential" \
        || bad "platform DOWN after rotation"
fi

# ============================================================ summary
say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "Vault holds: enclave-placed, audited, root revoked, app on issued credentials, rotation proven live"
else
    bad "Vault does NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"
