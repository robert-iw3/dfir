# The database. Each source named here has a reason to touch case records; everything else in
# the enclave is refused by the trailing rule, which is what stops a compromised frontend or
# receiver reading the evidence index.
#
# ir-vault is present because its database secrets engine mints and revokes the dynamic users
# the application tier runs on. Omit it and credential ISSUING is denied — the platform then
# fails to start for a reason that looks nothing like an intention.
Kind = "service-intentions"
Name = "ir-postgres"
Sources = [
  { Name = "ir-backend", Action = "allow" },
  { Name = "ir-worker",  Action = "allow" },
  { Name = "ir-puller",  Action = "allow" },
  { Name = "ir-vault",   Action = "allow" },
  { Name = "*",          Action = "deny"  },
]
