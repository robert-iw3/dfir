# Nothing dials Keycloak THROUGH the mesh: OIDC traffic (the gate, the backend, the browser
# via the broker) reaches it by name on the enclave network. Its mesh membership exists to
# reach Postgres, so inbound over Connect is refused outright.
Kind = "service-intentions"
Name = "ir-keycloak"
Sources = [
  { Name = "*", Action = "deny" },
]
