# The database. Each source named here has a reason to touch case records; everything else in
# the enclave is refused by the trailing rule, which is what stops a compromised frontend or
# receiver reading the evidence index.
Kind = "service-intentions"
Name = "ir-postgres"
Sources = [
  { Name = "ir-backend",     Action = "allow" },
  { Name = "ir-worker",      Action = "allow" },
  { Name = "ir-puller",      Action = "allow" },
  { Name = "ir-vault",       Action = "allow" },
  # The identity store's own database rides this same server; which DATABASE each side may
  # open is Postgres's rule (CONNECT grants in db-bootstrap.py), not the mesh's.
  { Name = "ir-keycloak",    Action = "allow" },
  # Component Health self-reports only; it runs no case-data query of its own.
  { Name = "ir-log-shipper", Action = "allow" },
  { Name = "*",              Action = "deny"  },
]
