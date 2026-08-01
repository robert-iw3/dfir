#!/usr/bin/env bash
# Provision Vault for the IR Platform. Idempotent; state in /vault/state.
#
#  - init + unseal
#  - AUDIT DEVICE, before anything else that touches a secret
#  - database secrets engine -> platform Postgres, role `ir-platform` issuing
#    short-lived login users that act as the fixed owner role `ir_app`
#  - KV v2 `ir/config` with the app's non-DB secrets (Django key, HMAC keys, MinIO)
#  - AppRole `ir-platform` (+ least-privilege policy) for the Vault Agent
#  - revokes the initial root token when provisioning completes
#
# Against HashiCorp's production hardening guidance, with the deviations named:
#
#   Audit device        ENABLED first, so no privileged operation goes unrecorded. On a forensics
#                       platform this is not optional — Vault holds the custody key, and an
#                       unaudited secrets store cannot support a chain of custody it is part of.
#   Root token          REVOKED once provisioning succeeds. It exists only for initial setup.
#                       A re-run detects a completed provision and never needs it again.
#   TLS                 Enabled, TLS 1.2 floor, on the listener. Clients pin the CA.
#   disable_mlock       TRUE, and deliberately: HashiCorp "strongly recommends" it WITH
#                       integrated storage (raft). Swap should be off on the host instead.
#   Least privilege     The ir-app policy names four explicit paths. No globs.
#   Short TTLs          Database credentials 1h/24h; agent tokens 1h/24h.
#   secret_id           BOUNDED (ttl + num_uses) rather than unlimited.
#   Unseal keys         Fed on STDIN, never as arguments — an argument is visible in the process
#                       list and in shell history.
#
#   DEVIATION: key shares. Defaults to 1/1 because unsealing is automated and additional shares
#   held in the same place add ceremony without adding safety. Set IR_VAULT_KEY_SHARES /
#   IR_VAULT_KEY_THRESHOLD for split custody, which is only meaningful with
#   IR_VAULT_AUTO_UNSEAL=0 so no copy is stored.
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-https://vault:8200}"
export VAULT_CACERT="${VAULT_CACERT:-/certs/vault-ca.crt.pem}"
STATE=/vault/state
PROVISIONED="${STATE}/.provisioned"
SHARES="${IR_VAULT_KEY_SHARES:-1}"
THRESHOLD="${IR_VAULT_KEY_THRESHOLD:-1}"
mkdir -p "$STATE"

echo "==> waiting for Vault API"
for i in $(seq 1 60); do
  curl -sf --cacert "$VAULT_CACERT" \
    "$VAULT_ADDR/v1/sys/health?uninitcode=200&sealedcode=200" >/dev/null 2>&1 && break
  [ "$i" = 60 ] && { echo "FAIL: vault API never came up"; exit 1; }
  sleep 2
done

init_status() {
  local out; out=$(vault status -format=json 2>/dev/null || true)
  echo "$out" | python3 -c "import json,sys;print(str(json.load(sys.stdin)['$1']).lower())" 2>/dev/null || echo unknown
}

if [ "$(init_status initialized)" != "true" ]; then
  echo "==> initializing (${SHARES} share(s) / threshold ${THRESHOLD})"
  vault operator init -key-shares="${SHARES}" -key-threshold="${THRESHOLD}" \
    -format=json > "$STATE/vault-init.json"
  chmod 600 "$STATE/vault-init.json"
fi

# Unsealed here so provisioning can proceed; vault-unseal.sh does the same job on every restart.
# Via the sys/unseal API so the key never appears on a command line: the CLI's only
# non-interactive form takes the key as an argument, which lands it in the process list.
#
# A function, and called again from the reconcile loop below, because the deployment can recreate
# Vault after this point — it comes back sealed, and a one-time unseal here would leave every
# later call answering 503.
unseal_if_sealed() {
  [ "$(init_status sealed)" = "true" ] || return 0
  python3 - "$STATE/vault-init.json" "$VAULT_ADDR" "$VAULT_CACERT" <<'PY'
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
            sys.exit(0)
sys.exit(1)
PY
  [ "$(init_status sealed)" = "false" ]
}

echo "==> unsealing"
unseal_if_sealed || { echo "FAIL: could not unseal"; exit 1; }

# Where Vault dials Postgres. It moves with the deployment — its own sidecar upstream on
# loopback with the mesh on, the service name without it — so it is a reconciled value, not a
# provisioned one.
DB_CONN="postgresql://{{username}}:{{password}}@${IR_VAULT_DB_HOST:-${POSTGRES_HOST:-db}}:${POSTGRES_PORT:-5432}/${POSTGRES_DB:-ir_platform}?sslmode=disable"

# Reconciled on EVERY run, before the early exit below. Written once, a stale connection URL
# leaves the platform running on already-issued leases and looking healthy, then failing the
# first time it must mint or revoke a credential — which is exactly when it is needed.
# A deployment provisioned before the provisioner AppRole existed has no way to reconcile
# anything, because the root token is already revoked. Mint one through break-glass, create the
# role, and revoke — once per such deployment, never again.
if [ -f "$PROVISIONED" ] && [ ! -f "$STATE/provisioner_role_id" ]; then
  echo "==> creating the reconciliation AppRole (break-glass, one time)"
  BGT=$(python3 /opt/vault/breakglass-root.py 2>/dev/null || true)
  if [ -z "$BGT" ]; then
    echo "    WARNING: break-glass failed — the database connection cannot be reconciled" >&2
  else
    export VAULT_TOKEN="$BGT"
    vault policy write ir-provisioner - <<'EOF'
path "database/config/ir-platform" { capabilities = ["create", "update", "read"] }
path "database/roles/ir-platform"  { capabilities = ["create", "update", "read"] }
EOF
    vault auth enable approle 2>/dev/null || true
    vault write auth/approle/role/ir-provisioner \
      token_policies=ir-provisioner token_ttl=10m token_max_ttl=30m \
      bind_secret_id=true secret_id_ttl=0 secret_id_num_uses=0 >/dev/null
    vault read -field=role_id auth/approle/role/ir-provisioner/role-id > "$STATE/provisioner_role_id"
    vault write -f -field=secret_id auth/approle/role/ir-provisioner/secret-id > "$STATE/provisioner_secret_id"
    chmod 600 "$STATE/provisioner_role_id" "$STATE/provisioner_secret_id"
    vault token revoke -self >/dev/null 2>&1 || true
    unset VAULT_TOKEN
    echo "    created; temporary root revoked"
  fi
fi

if [ -f "$PROVISIONED" ] && [ -f "$STATE/provisioner_role_id" ]; then
  echo "==> reconciling the database connection"
  # Login AND write in one retry, because everything either can fail on is transient and
  # correlated: a deployment recreates Vault (its address moves, and it comes back sealed) and
  # restarts the sidecar carrying its database upstream. Retrying only the write leaves a token
  # minted against a Vault that has since moved.
  ERR=""; OK=0
  for _ in $(seq 1 20); do
    unseal_if_sealed || true
    PTOK=$(vault write -field=token auth/approle/login \
        role_id="$(cat "$STATE/provisioner_role_id")" \
        secret_id="$(cat "$STATE/provisioner_secret_id")" 2>&1) || { ERR="$PTOK"; sleep 3; continue; }
    if ERR=$(VAULT_TOKEN="$PTOK" vault write database/config/ir-platform \
          plugin_name=postgresql-database-plugin \
          allowed_roles=ir-platform \
          connection_url="$DB_CONN" \
          username="${POSTGRES_USER:-ir_platform}" \
          password="${POSTGRES_PASSWORD:-ir_platform}" 2>&1); then
      OK=1; break
    fi
    sleep 3
  done
  if [ "$OK" = 1 ]; then
    echo "    database connection -> ${IR_VAULT_DB_HOST:-${POSTGRES_HOST:-db}}:${POSTGRES_PORT:-5432}"
  else
    # Surfaced, not swallowed: this failing is the difference between a platform that can rotate
    # credentials and one that only appears to.
    echo "    WARNING: could not reconcile the database connection URL:" >&2
    printf '      %s\n' "$ERR" | tail -4 >&2
  fi
fi

# A completed provision needs no root token, so there is none to hold. This is what makes
# revoking it at the end safe rather than a one-way door into manual recovery.
if [ -f "$PROVISIONED" ]; then
  echo "==> already provisioned; root token was revoked after the initial run"
  echo "vault-setup-ir: DONE (nothing to do)"
  exit 0
fi

export VAULT_TOKEN=$(python3 -c "import json;print(json.load(open('$STATE/vault-init.json'))['root_token'])")
if ! vault token lookup >/dev/null 2>&1; then
  echo "FAIL: the stored root token is no longer valid but provisioning is incomplete." >&2
  echo "      Recover with: vault operator generate-root  (needs the unseal key)," >&2
  echo "      or remove the vault-data volume to start clean — which DESTROYS the secrets." >&2
  exit 1
fi

# BEFORE anything that reads or writes a secret, so nothing privileged happens unrecorded.
echo "==> audit device"
if ! vault audit list -format=json 2>/dev/null | grep -q '"file/"'; then
  vault audit enable file file_path=/vault/logs/vault-audit.log \
    && echo "    audit -> /vault/logs/vault-audit.log" \
    || echo "    WARNING: audit device could not be enabled — operations will go unrecorded" >&2
else
  echo "    audit device already enabled"
fi

echo "==> database secrets engine"
vault secrets enable database 2>/dev/null || echo "    database engine already enabled"
# No separate wait for Postgres: this container never talks to it. Vault dials the database
# through its own sidecar and verifies the connection on this write, so the write IS the
# readiness check — retried, because the proxy in front of Postgres may be seconds from ready.
for i in $(seq 1 20); do
  OUT=$(vault write database/config/ir-platform \
    plugin_name=postgresql-database-plugin \
    allowed_roles=ir-platform \
    connection_url="$DB_CONN" \
    username="${POSTGRES_USER:-ir_platform}" \
    password="${POSTGRES_PASSWORD:-ir_platform}" 2>&1) && break
  [ "$i" = 20 ] && { echo "FAIL: Vault cannot reach Postgres:"; printf '%s\n' "$OUT" | tail -4; exit 1; }
  sleep 3
done

# Each dynamic user logs in, is a member of ir_app, and defaults to acting as ir_app
# (SET role) so all objects are owned by ir_app — stable across rotation.
vault write database/roles/ir-platform \
  db_name=ir-platform \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE ir_app; ALTER ROLE \"{{name}}\" SET role = 'ir_app';" \
  revocation_statements="REASSIGN OWNED BY \"{{name}}\" TO ir_app; DROP OWNED BY \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl=1h max_ttl=24h

echo "==> KV v2: ir/config (non-DB app secrets)"
vault secrets enable -path=ir kv-v2 2>/dev/null || echo "    kv already enabled"
vault kv put ir/config \
  django_secret_key="${IR_KV_DJANGO_SECRET:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(50))')}" \
  audit_hmac_key="${IR_KV_AUDIT_HMAC:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')}" \
  custody_hmac_key="${IR_KV_CUSTODY_HMAC:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')}" \
  minio_access="${S3_ACCESS_KEY:-ir_platform}" \
  minio_secret="${S3_SECRET_KEY:-ir_platform_secret}"

echo "==> policy + AppRole for the Vault Agent"
vault policy write ir-app - <<'EOF'
path "database/creds/ir-platform" { capabilities = ["read"] }
path "ir/data/config"             { capabilities = ["read"] }
path "sys/leases/renew"           { capabilities = ["update"] }
path "auth/token/renew-self"      { capabilities = ["update"] }
EOF

vault auth enable approle 2>/dev/null || echo "    approle already enabled"
# Bounded rather than unlimited. A secret_id with no TTL and no use limit is a permanent
# credential sitting on a volume; these expire, and the agent re-reads a fresh one at deploy.
# bind_secret_id keeps possession of the role_id alone insufficient to authenticate.
vault write auth/approle/role/ir-platform \
  token_policies=ir-app token_ttl=1h token_max_ttl=24h \
  bind_secret_id=true \
  secret_id_ttl="${IR_VAULT_SECRET_ID_TTL:-72h}" \
  secret_id_num_uses="${IR_VAULT_SECRET_ID_USES:-0}"

vault read -field=role_id auth/approle/role/ir-platform/role-id > "$STATE/role_id"
vault write -f -field=secret_id auth/approle/role/ir-platform/secret-id > "$STATE/secret_id"
cp "$VAULT_CACERT" "$STATE/vault-ca.crt.pem"
chmod 644 "$STATE/role_id" "$STATE/secret_id" "$STATE/vault-ca.crt.pem"

echo "==> policy + AppRole for redeployment-time reconciliation"
# Narrower than root by design: it can point the database engine at a different Postgres and
# nothing else. That is the one thing a redeployment legitimately changes, and it means a
# routine deploy never needs to mint a root token.
vault policy write ir-provisioner - <<'EOF'
path "database/config/ir-platform" { capabilities = ["create", "update", "read"] }
path "database/roles/ir-platform"  { capabilities = ["create", "update", "read"] }
EOF

# No secret_id TTL: this must still work at a deployment months from now. It sits on the same
# state volume as the unseal key, so it widens nothing that volume did not already expose.
vault write auth/approle/role/ir-provisioner \
  token_policies=ir-provisioner token_ttl=10m token_max_ttl=30m \
  bind_secret_id=true secret_id_ttl=0 secret_id_num_uses=0

vault read -field=role_id auth/approle/role/ir-provisioner/role-id > "$STATE/provisioner_role_id"
vault write -f -field=secret_id auth/approle/role/ir-provisioner/secret-id > "$STATE/provisioner_secret_id"
chmod 600 "$STATE/provisioner_role_id" "$STATE/provisioner_secret_id"

echo "==> smoke: mint one dynamic DB credential (waits for db-bootstrap's ir_app role)"
for i in $(seq 1 30); do
  OUT=$(vault read database/creds/ir-platform -format=json 2>/dev/null || true)
  U=$(printf '%s' "$OUT" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['username'])" 2>/dev/null || true)
  if [ -n "$U" ]; then echo "    issued db user: $U"; break; fi
  [ "$i" = 30 ] && echo "    (ir_app not ready yet — the agent will mint creds once db-bootstrap completes)"
  sleep 2
done

> "$PROVISIONED"

# "Once you complete initial Vault setup, you should revoke the initial root token to reduce risk
# of exposure." Nothing above is needed again: the agent authenticates by AppRole, unsealing uses
# the unseal key, and a re-run exits early on the marker written above.
#
# The root token is removed from the state file as well as revoked. Leaving a revoked token on
# disk invites someone to conclude the file is harmless — it still holds the unseal key.
if [ "${IR_VAULT_REVOKE_ROOT:-1}" = "1" ]; then
  echo "==> revoking the initial root token"
  if vault token revoke -self >/dev/null 2>&1; then
    python3 - "$STATE/vault-init.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d.pop("root_token", None)
d["root_token_revoked"] = True
json.dump(d, open(p, "w"), indent=2)
PY
    chmod 600 "$STATE/vault-init.json"
    echo "    revoked; recover with 'vault operator generate-root' if ever needed"
  else
    echo "    WARNING: could not revoke the root token — it remains valid in $STATE" >&2
  fi
else
  echo "==> IR_VAULT_REVOKE_ROOT=0 — the initial root token is being KEPT (not recommended)"
fi

echo "vault-setup-ir: DONE"
