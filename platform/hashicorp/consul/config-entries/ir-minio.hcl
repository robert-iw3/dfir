# The object store: the captured memory images themselves. The narrowest allow-list in the
# enclave, because a single object here is a host's entire RAM.
Kind = "service-intentions"
Name = "ir-minio"
Sources = [
  { Name = "ir-backend", Action = "allow" },
  { Name = "ir-worker",  Action = "allow" },
  { Name = "ir-puller",  Action = "allow" },
  # Web-tier access records into the private ir-logs bucket. It writes logs and reads nothing
  # else; the bucket is separate from evidence and carved regions.
  { Name = "ir-log-shipper", Action = "allow" },
  { Name = "*",          Action = "deny"  },
]
