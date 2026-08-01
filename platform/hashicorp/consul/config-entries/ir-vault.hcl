# Vault issues credentials outward; nothing calls INTO it through the mesh, because its agent
# authenticates over the loopback it shares with its own sidecar. A deny-all therefore costs
# nothing and closes the secrets store to lateral traffic.
Kind = "service-intentions"
Name = "ir-vault"
Sources = [
  { Name = "*", Action = "deny" },
]
