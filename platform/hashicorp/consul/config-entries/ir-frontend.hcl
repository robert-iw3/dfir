# Not a destination for anything. Stated rather than left to the global default, so a service
# added later cannot quietly gain reach to it.
Kind = "service-intentions"
Name = "ir-frontend"
Sources = [
  { Name = "*", Action = "deny" },
]
