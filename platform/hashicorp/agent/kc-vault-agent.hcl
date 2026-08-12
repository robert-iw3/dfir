# Vault Agent for Keycloak. Auto-auths with Keycloak's OWN AppRole — a policy that reads only
# database/creds/keycloak — renders the credential for Keycloak to source, and keeps the lease
# renewed.
pid_file = "/vault/agent/kc-vault-agent.pid"

vault {
  address = "https://vault:8200"
  ca_cert = "/vault/state/vault-ca.crt.pem"
  retry { num_retries = 10 }
}

auto_auth {
  method {
    type = "approle"
    config = {
      role_id_file_path                   = "/vault/state/kc_role_id"
      secret_id_file_path                 = "/vault/state/kc_secret_id"
      remove_secret_id_file_after_reading = false
    }
  }
  sink {
    type   = "file"
    config = { path = "/vault/agent/agent-token" }
  }
}

template {
  source      = "/vault/agent/kc-db-env.tmpl"
  destination = "/vault/secrets/kc-db.env"
}
