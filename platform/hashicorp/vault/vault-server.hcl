# Vault server (integrated raft storage + TLS) for the IR Platform.
# Reuses the standalone-server shape from containers/vault; certs come from the
# vault-certs-init step (generate_certs.py) on a shared volume.
ui           = true
cluster_name = "ir-vault"
# Strongly recommended BY HASHICORP when storage is integrated raft; disable swap on the host
# instead. Not an oversight to be "fixed".
disable_mlock = true

# Vault 2.0 authenticates the generate-root flow by default, which would close this platform's
# break-glass path: the initial root token is revoked at provisioning, so credential rotation
# has no standing authority and mints a temporary root through this flow instead. Re-opening it
# changes who may ORCHESTRATE the flow, not who may complete it — completion still requires the
# unseal key quorum, the listener is reachable only from the enclave's internal network, and
# every step lands in the audit device.
enable_unauthenticated_access = ["generate-root"]

api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/certs/vault-0.crt.pem"
  tls_key_file    = "/certs/vault-0.key.pem"
  tls_min_version = "tls12"
  telemetry { unauthenticated_metrics_access = false }
}

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-0"
}

log_level  = "info"
log_format = "json"
