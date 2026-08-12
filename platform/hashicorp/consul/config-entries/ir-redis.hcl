# The task queue. Only the two ends of a Celery job have a reason to touch it: the backend
# enqueues, the worker consumes.
Kind = "service-intentions"
Name = "ir-redis"
Sources = [
  { Name = "ir-backend", Action = "allow" },
  { Name = "ir-worker",  Action = "allow" },
  # The SSO gate holds analyst sessions here (server-side session management), in database 1.
  { Name = "ir-oauth2-proxy", Action = "allow" },
  { Name = "*",          Action = "deny"  },
]
