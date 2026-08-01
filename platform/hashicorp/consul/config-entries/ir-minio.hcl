# The object store: the captured memory images themselves. The narrowest allow-list in the
# enclave, because a single object here is a host's entire RAM.
Kind = "service-intentions"
Name = "ir-minio"
Sources = [
  { Name = "ir-backend", Action = "allow" },
  { Name = "ir-worker",  Action = "allow" },
  { Name = "ir-puller",  Action = "allow" },
  { Name = "*",          Action = "deny"  },
]
