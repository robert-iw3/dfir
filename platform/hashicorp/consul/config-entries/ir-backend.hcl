# The API. Reached by the UI, and by the puller reporting an arrival — not by the data tier,
# which has no business calling back up the stack.
Kind = "service-intentions"
Name = "ir-backend"
Sources = [
  { Name = "ir-frontend", Action = "allow" },
  { Name = "ir-puller",   Action = "allow" },
  { Name = "*",           Action = "deny"  },
]
