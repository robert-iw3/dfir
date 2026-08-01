# Vault Agent for the IR Platform app tier.
# Auto-auths via AppRole (role_id/secret_id from the setup step), renders the app's
# secrets — dynamic Postgres creds + KV — into a shared file the backend/worker source,
# and auto-renews the DB lease so the credential stays valid without app restarts.
pid_file = "/vault/agent/vault-agent.pid"

vault {
  address = "https://vault:8200"
  ca_cert = "/vault/state/vault-ca.crt.pem"
  retry { num_retries = 10 }
}

auto_auth {
  method {
    type = "approle"
    config = {
      role_id_file_path                   = "/vault/state/role_id"
      secret_id_file_path                 = "/vault/state/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }
  sink {
    type   = "file"
    config = { path = "/vault/agent/agent-token" }
  }
}

template {
  source      = "/vault/agent/app-env.tmpl"
  destination = "/vault/secrets/app.env"
  # Render once creds are available; agent keeps the DB lease renewed in the background.
}
