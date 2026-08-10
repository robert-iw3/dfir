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

# The unseal material is read at EVERY start by the server itself, which runs unprivileged
# (uid 65535). Root-owned 0600 means only `podman exec --user root` can read it, which makes
# unsealing a deployment step rather than a property of the server coming back — and a Vault
# restarted by anything other than a deploy then stays sealed, answering health checks and
# serving nothing. Ownership moves to the account that needs it; the mode does not change, so
# the key is still readable by exactly one identity.
own_unseal_material() {
  chmod 600 "$STATE/vault-init.json"
  chown "$(id -u vault 2>/dev/null || echo 65535)":"$(id -g vault 2>/dev/null || echo 65535)" \
    "$STATE/vault-init.json" 2>/dev/null || true
}

if [ "$(init_status initialized)" != "true" ]; then
  echo "==> initializing (${SHARES} share(s) / threshold ${THRESHOLD})"
  vault operator init -key-shares="${SHARES}" -key-threshold="${THRESHOLD}" \
    -format=json > "$STATE/vault-init.json"
  own_unseal_material
fi

# Reconciled on EVERY run, not only at init. A Vault initialized before this ownership was
# required would otherwise keep the old one for the life of the volume, and the defect it
# causes — a restart that stays sealed — appears far from here and long afterwards.
[ -s "$STATE/vault-init.json" ] && own_unseal_material

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
KC_CONN="postgresql://{{username}}:{{password}}@${IR_VAULT_DB_HOST:-${POSTGRES_HOST:-db}}:${POSTGRES_PORT:-5432}/${KEYCLOAK_POSTGRES_DB:-keycloak}?sslmode=disable"

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
path "database/config/keycloak"    { capabilities = ["create", "update", "read"] }
path "database/roles/keycloak"     { capabilities = ["create", "update", "read"] }
# Minting an agent a fresh secret_id. The agents' secret_ids EXPIRE by design, so a deploy
# that cannot mint them leaves both agents unable to authenticate once the TTL passes —
# the whole app tier down, with no path back short of break-glass.
path "auth/approle/role/ir-platform/secret-id" { capabilities = ["update"] }
path "auth/approle/role/ir-keycloak/secret-id" { capabilities = ["update"] }
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

  # The identity store's engine, reconciled the same way — and CREATED here on a deployment
  # provisioned before it existed. The role's TTLs ride along so a lease change in this
  # file actually lands.
  echo "==> reconciling the keycloak database connection"
  ERR=""; OK=0; KC_DENIED=0
  for _ in $(seq 1 20); do
    unseal_if_sealed || true
    PTOK=$(vault write -field=token auth/approle/login \
        role_id="$(cat "$STATE/provisioner_role_id")" \
        secret_id="$(cat "$STATE/provisioner_secret_id")" 2>&1) || { ERR="$PTOK"; sleep 3; continue; }
    if ERR=$(VAULT_TOKEN="$PTOK" vault write database/config/keycloak \
          plugin_name=postgresql-database-plugin \
          allowed_roles=keycloak \
          connection_url="$KC_CONN" \
          username="${POSTGRES_USER:-ir_platform}" \
          password="${POSTGRES_PASSWORD:-ir_platform}" 2>&1); then
      ERR=$(VAULT_TOKEN="$PTOK" vault write database/roles/keycloak \
          db_name=keycloak \
          creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE kc_app; ALTER ROLE \"{{name}}\" SET role = 'kc_app';" \
          revocation_statements="REASSIGN OWNED BY \"{{name}}\" TO kc_app; DROP OWNED BY \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
          default_ttl="${IR_VAULT_KC_TTL:-24h}" max_ttl="${IR_VAULT_KC_MAX_TTL:-768h}" 2>&1) \
        && { OK=1; break; }
    fi
    # A refusal is not transient: the STORED provisioner policy predates these paths — a
    # policy is written at provision time and nothing rewrites it, the same never-updates
    # trap as every other bootstrap. Retrying a 403 nineteen more times only hides it.
    case "$ERR" in *"permission denied"*) KC_DENIED=1; break ;; esac
    sleep 3
  done
  if [ "$OK" = 1 ]; then
    echo "    keycloak connection + role -> ${IR_VAULT_DB_HOST:-${POSTGRES_HOST:-db}}:${POSTGRES_PORT:-5432}"
  elif [ "$KC_DENIED" = 1 ]; then
    echo "    provisioner policy predates the keycloak paths — converging through break-glass"
  else
    echo "    WARNING: could not reconcile the keycloak engine — identity has no credential path:" >&2
    printf '      %s\n' "$ERR" | tail -4 >&2
  fi

  # The agents' secret_ids, reissued every deploy.
  #
  # They carry a TTL (72h by default), so the credential on the state volume is perishable
  # while the file holding it is not. Once it expires the agent authenticates forever against
  # a secret_id Vault no longer knows, stops rendering, and the leased Postgres role it last
  # wrote is revoked out from under the app tier — which then cannot start, with nothing in
  # the deploy saying why. Minting a fresh one every run is what makes the TTL survivable.
  echo "==> reissuing the agent credentials"
  SID_DENIED=0
  for role in ir-platform ir-keycloak; do
    case "$role" in
      ir-platform) id_file="$STATE/secret_id" ;;
      ir-keycloak) id_file="$STATE/kc_secret_id" ;;
    esac
    ERR=""; OK=0
    for _ in $(seq 1 10); do
      unseal_if_sealed || true
      PTOK=$(vault write -field=token auth/approle/login \
          role_id="$(cat "$STATE/provisioner_role_id")" \
          secret_id="$(cat "$STATE/provisioner_secret_id")" 2>&1) || { ERR="$PTOK"; sleep 3; continue; }
      # Written to a temporary file first: truncating the live one and then failing leaves the
      # agent with an empty credential, which is worse than the stale one it had.
      if ERR=$(VAULT_TOKEN="$PTOK" vault write -f -field=secret_id \
            "auth/approle/role/${role}/secret-id" 2>&1 > "${id_file}.new"); then
        mv "${id_file}.new" "$id_file"; chmod 644 "$id_file"; OK=1; break
      fi
      rm -f "${id_file}.new"
      # Not transient: the STORED policy predates these paths. Converged below, through
      # break-glass, rather than retried into the same refusal.
      case "$ERR" in *"permission denied"*) SID_DENIED=1; break ;; esac
      sleep 3
    done
    if [ "$OK" = 1 ]; then
      echo "    ${role}: fresh secret_id issued"
    elif [ "$SID_DENIED" = 1 ]; then
      echo "    provisioner policy predates the secret-id paths — converging through break-glass"
      break
    else
      echo "    WARNING: ${role} was not reissued a secret_id — its agent stops at the TTL:" >&2
      printf '      %s\n' "$ERR" | tail -4 >&2
    fi
  done
fi

# A deployment provisioned before Keycloak existed in Vault: policies and AppRoles are
# deliberately outside the provisioner's reach, so they are converged once through
# break-glass — the AppRole when its credential file is absent, the stored policies (and
# the writes the stale policy refused) when a reconcile above was denied.
if [ -f "$PROVISIONED" ] && { [ ! -f "$STATE/kc_role_id" ] \
     || [ "${KC_DENIED:-0}" = 1 ] || [ "${SID_DENIED:-0}" = 1 ]; }; then
  echo "==> converging Keycloak's Vault identity (break-glass, one time)"
  BGT=$(python3 /opt/vault/breakglass-root.py 2>/dev/null || true)
  if [ -z "$BGT" ]; then
    echo "    WARNING: break-glass failed — Keycloak has no credential path" >&2
  else
    export VAULT_TOKEN="$BGT"
    # The stored policies converge to the file's shape — both of them, so the next deploy's
    # reconcile succeeds as the provisioner instead of landing back here.
    vault policy write ir-provisioner - <<'EOF'
path "database/config/ir-platform" { capabilities = ["create", "update", "read"] }
path "database/roles/ir-platform"  { capabilities = ["create", "update", "read"] }
path "database/config/keycloak"    { capabilities = ["create", "update", "read"] }
path "database/roles/keycloak"     { capabilities = ["create", "update", "read"] }
# Minting an agent a fresh secret_id. The agents' secret_ids EXPIRE by design, so a deploy
# that cannot mint them leaves both agents unable to authenticate once the TTL passes —
# the whole app tier down, with no path back short of break-glass.
path "auth/approle/role/ir-platform/secret-id" { capabilities = ["update"] }
path "auth/approle/role/ir-keycloak/secret-id" { capabilities = ["update"] }
EOF
    vault policy write kc-db - <<'EOF'
path "database/creds/keycloak" { capabilities = ["read"] }
path "sys/leases/renew"        { capabilities = ["update"] }
path "auth/token/renew-self"   { capabilities = ["update"] }
EOF
    vault auth enable approle 2>/dev/null || true
    vault write auth/approle/role/ir-keycloak \
      token_policies=kc-db token_ttl=1h token_max_ttl=24h \
      bind_secret_id=true \
      secret_id_ttl="${IR_VAULT_SECRET_ID_TTL:-72h}" \
      secret_id_num_uses="${IR_VAULT_SECRET_ID_USES:-0}" >/dev/null
    vault read -field=role_id auth/approle/role/ir-keycloak/role-id > "$STATE/kc_role_id"
    vault write -f -field=secret_id auth/approle/role/ir-keycloak/secret-id > "$STATE/kc_secret_id"
    chmod 644 "$STATE/kc_role_id" "$STATE/kc_secret_id"
    if [ "${KC_DENIED:-0}" = 1 ]; then
      # The writes the stale policy refused, done now with the token in hand rather than
      # leaving identity without a credential path until the next deploy.
      vault write database/config/keycloak \
        plugin_name=postgresql-database-plugin \
        allowed_roles=keycloak \
        connection_url="$KC_CONN" \
        username="${POSTGRES_USER:-ir_platform}" \
        password="${POSTGRES_PASSWORD:-ir_platform}" >/dev/null \
        && vault write database/roles/keycloak \
          db_name=keycloak \
          creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE kc_app; ALTER ROLE \"{{name}}\" SET role = 'kc_app';" \
          revocation_statements="REASSIGN OWNED BY \"{{name}}\" TO kc_app; DROP OWNED BY \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
          default_ttl="${IR_VAULT_KC_TTL:-24h}" max_ttl="${IR_VAULT_KC_MAX_TTL:-768h}" >/dev/null \
        && echo "    keycloak engine written" \
        || echo "    WARNING: keycloak engine write failed even with root — is the database up?" >&2
    fi
    if [ "${SID_DENIED:-0}" = 1 ]; then
      # The reissue the stale policy refused. Both agents, with the token in hand: leaving
      # either on an expired secret_id is the outage this whole path exists to end.
      for role in ir-platform ir-keycloak; do
        case "$role" in
          ir-platform) id_file="$STATE/secret_id" ;;
          ir-keycloak) id_file="$STATE/kc_secret_id" ;;
        esac
        if vault write -f -field=secret_id \
             "auth/approle/role/${role}/secret-id" > "${id_file}.new" 2>/dev/null; then
          mv "${id_file}.new" "$id_file"; chmod 644 "$id_file"
          echo "    ${role}: fresh secret_id issued"
        else
          rm -f "${id_file}.new"
          echo "    WARNING: ${role} secret_id reissue failed even with root" >&2
        fi
      done
    fi
    vault token revoke -self >/dev/null 2>&1 || true
    unset VAULT_TOKEN
    echo "    converged; temporary root revoked"
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

echo "==> database secrets engine: keycloak"
# A SEPARATE database config, so the two engines cannot issue each other's credentials:
# `allowed_roles` names only this role, and the connection URL reaches only this database.
# Keycloak stores password hashes and session state; a credential minted here that could also
# open the evidence store would make the separation enforced in db-bootstrap.py decorative.
for i in $(seq 1 20); do
  OUT=$(vault write database/config/keycloak \
    plugin_name=postgresql-database-plugin \
    allowed_roles=keycloak \
    connection_url="$KC_CONN" \
    username="${POSTGRES_USER:-ir_platform}" \
    password="${POSTGRES_PASSWORD:-ir_platform}" 2>&1) && break
  [ "$i" = 20 ] && { echo "FAIL: Vault cannot reach the keycloak database:"; printf '%s\n' "$OUT" | tail -4; exit 1; }
  sleep 3
done

# Same shape as the application's: each dynamic user is a member of the stable owner role and
# acts as it, so objects survive rotation. Keycloak runs its own schema migrations at start-up,
# so stable ownership matters here for the same reason it does for Django's.
#
# Longer TTLs than the application's, deliberately: Keycloak pools connections and reads its
# credential once at start — it cannot pick up a re-rendered file without a restart. At
# max_ttl the user is dropped and every pooled connection dies mid-session. So the lease is
# sized to outlive any deploy cadence (every deploy recreates the Vault group and mints a
# fresh lease); the agent renews within max_ttl as usual.
vault write database/roles/keycloak \
  db_name=keycloak \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE kc_app; ALTER ROLE \"{{name}}\" SET role = 'kc_app';" \
  revocation_statements="REASSIGN OWNED BY \"{{name}}\" TO kc_app; DROP OWNED BY \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="${IR_VAULT_KC_TTL:-24h}" max_ttl="${IR_VAULT_KC_MAX_TTL:-768h}"

echo "==> KV v2: ir/config (non-DB app secrets)"
vault secrets enable -path=ir kv-v2 2>/dev/null || echo "    kv already enabled"

# GENERATED ONCE, THEN PRESERVED FOREVER.
#
# `vault kv put` replaces the whole secret, and this script runs on every deploy. Generating
# defaults inline therefore MINTED NEW KEYS EVERY TIME:
#
#   audit_hmac_key    every existing audit row's signature stops verifying — the platform
#                     reports its own tamper-evidence as BROKEN, and cannot tell a rotated
#                     key from an actual forgery
#   custody_hmac_key  every existing custody seal stops verifying — on a forensic platform
#                     that is the evidentiary chain for material already collected
#   django_secret_key every issued session and signed token is invalidated
#
# These are identity for data already at rest. A value that exists is kept; only a MISSING
# one is created. Rotation is a deliberate act with a migration behind it, never a side
# effect of redeploying — so an explicit IR_KV_* override still wins, and says so.
kv_get() { vault kv get -field="$1" ir/config 2>/dev/null || true; }
kv_keep() { # field  env-override  entropy-bytes
    local field="$1" override="$2" bytes="$3"
    local existing; existing="$(kv_get "${field}")"
    if [ -n "${override}" ]; then
        [ -n "${existing}" ] && [ "${override}" != "${existing}" ] \
            && echo "    ${field}: REPLACED from IR_KV_* override — anything signed with the previous key stops verifying" >&2
        printf '%s' "${override}"
    elif [ -n "${existing}" ]; then
        printf '%s' "${existing}"
    else
        echo "    ${field}: generated (first deploy for this Vault store)" >&2
        python3 -c "import secrets,sys;print(secrets.token_urlsafe(int(sys.argv[1])))" "${bytes}"
    fi
}
KV_DJANGO="$(kv_keep django_secret_key "${IR_KV_DJANGO_SECRET:-}" 50)"
KV_AUDIT="$(kv_keep audit_hmac_key "${IR_KV_AUDIT_HMAC:-}" 32)"
KV_CUSTODY="$(kv_keep custody_hmac_key "${IR_KV_CUSTODY_HMAC:-}" 32)"
[ -n "${KV_DJANGO}" ] && [ -n "${KV_AUDIT}" ] && [ -n "${KV_CUSTODY}" ] || {
    echo "    FAILED to resolve the KV signing keys — refusing to write a partial ir/config" >&2
    exit 1
}
vault kv put ir/config \
  django_secret_key="${KV_DJANGO}" \
  audit_hmac_key="${KV_AUDIT}" \
  custody_hmac_key="${KV_CUSTODY}" \
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

echo "==> policy + AppRole for Keycloak's agent"
# Its own identity, not a second path on ir-app: neither agent can read the other's
# credential, so a compromised app tier cannot ask Vault for the identity store's password.
vault policy write kc-db - <<'EOF'
path "database/creds/keycloak" { capabilities = ["read"] }
path "sys/leases/renew"        { capabilities = ["update"] }
path "auth/token/renew-self"   { capabilities = ["update"] }
EOF

vault write auth/approle/role/ir-keycloak \
  token_policies=kc-db token_ttl=1h token_max_ttl=24h \
  bind_secret_id=true \
  secret_id_ttl="${IR_VAULT_SECRET_ID_TTL:-72h}" \
  secret_id_num_uses="${IR_VAULT_SECRET_ID_USES:-0}"

vault read -field=role_id auth/approle/role/ir-keycloak/role-id > "$STATE/kc_role_id"
vault write -f -field=secret_id auth/approle/role/ir-keycloak/secret-id > "$STATE/kc_secret_id"
chmod 644 "$STATE/kc_role_id" "$STATE/kc_secret_id"

echo "==> policy + AppRole for redeployment-time reconciliation"
# Narrower than root by design: it can point the database engine at a different Postgres and
# nothing else. That is the one thing a redeployment legitimately changes, and it means a
# routine deploy never needs to mint a root token.
vault policy write ir-provisioner - <<'EOF'
path "database/config/ir-platform" { capabilities = ["create", "update", "read"] }
path "database/roles/ir-platform"  { capabilities = ["create", "update", "read"] }
path "database/config/keycloak"    { capabilities = ["create", "update", "read"] }
path "database/roles/keycloak"     { capabilities = ["create", "update", "read"] }
# Minting an agent a fresh secret_id. The agents' secret_ids EXPIRE by design, so a deploy
# that cannot mint them leaves both agents unable to authenticate once the TTL passes —
# the whole app tier down, with no path back short of break-glass.
path "auth/approle/role/ir-platform/secret-id" { capabilities = ["update"] }
path "auth/approle/role/ir-keycloak/secret-id" { capabilities = ["update"] }
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
    own_unseal_material
    echo "    revoked; recover with 'vault operator generate-root' if ever needed"
  else
    echo "    WARNING: could not revoke the root token — it remains valid in $STATE" >&2
  fi
else
  echo "==> IR_VAULT_REVOKE_ROOT=0 — the initial root token is being KEPT (not recommended)"
fi

echo "vault-setup-ir: DONE"
