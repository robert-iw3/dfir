"""
Django settings for the IR analysis platform.

Every environment-specific knob comes from the environment (12-factor); there are
safe local defaults so `manage.py` works without a full env in dev, but secrets are
never hardcoded. See platform/.env.example for the full list.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_vault_env():
    """Adopt the Vault Agent's rendered secrets, for EVERY process in this container.

    The entrypoint sources this file before exec'ing the server, but `manage.py` run through
    `podman exec` never runs the entrypoint and would otherwise hold a different custody key
    from the API — which surfaces as a seal failure that reads as tampering.
    """
    path = os.environ.get("IR_VAULT_SECRETS_FILE", "/vault/secrets/app.env")
    if os.environ.get("IR_VAULT", "0") != "1" or not os.path.isfile(path):
        return
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line = line[7:].lstrip() if line.startswith("export ") else line
                key, sep, val = line.partition("=")
                if not sep:
                    continue
                # The rendered file is authoritative: it holds the CURRENT lease, and the
                # image environment holds whatever was baked in at build or compose time.
                os.environ[key.strip()] = val.strip().strip('"').strip("'")
    except OSError:
        # A container without the mount runs on its image environment, as before.
        pass


_load_vault_env()


def _env(key, default=None):
    val = os.environ.get(key)
    return val if val not in (None, "") else default


def _bool(key, default=False):
    return _env(key, str(default)).lower() in ("1", "true", "yes", "on")


SECRET_KEY = _env("DJANGO_SECRET_KEY", "dev-insecure-key-change-me")
DEBUG = _bool("DJANGO_DEBUG", True)
ALLOWED_HOSTS = _env("DJANGO_ALLOWED_HOSTS", "*").split(",")
# The SPA and API are same-origin behind nginx in prod; CORS is opened only in dev.
CORS_ALLOW_ALL_ORIGINS = DEBUG
CSRF_TRUSTED_ORIGINS = [
    o for o in _env("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",") if o
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Required for GinIndex on Finding.mitre, which serves the ATT&CK containment filter.
    # Django refuses to start without it rather than ignoring the index silently, which is
    # the preferable failure: an index the planner never gets is worse than a hard error.
    "django.contrib.postgres",
    "rest_framework",
    "rest_framework.authtoken",
    "corsheaders",
    "cases",
    # Operational telemetry — API request logs and browser errors. Its own database; see
    # opslog/models.py for why it is not in the evidence store.
    "opslog",
    "correlation",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Last, so it wraps the view: the duration recorded is what the caller waited for, and an
    # exception escaping the view is captured with its traceback rather than only reaching
    # container stdout, where nobody reading the UI can get to it.
    "opslog.middleware.RequestLogMiddleware",
    # Inside the request log so it sees the status the view returned. Records every successful
    # write that no call site audited itself, which is what keeps coverage from depending on
    # someone remembering to instrument a new route.
    "cases.auditmiddleware.AuditWriteMiddleware",
]

ROOT_URLCONF = "ir_platform.urls"
WSGI_APPLICATION = "ir_platform.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": [
            "django.template.context_processors.request",
            "django.contrib.auth.context_processors.auth",
            "django.contrib.messages.context_processors.messages",
        ]},
    },
]

DATABASES = {
    "default": {
        "ENGINE": "ir_platform.vaultdb",
        "NAME": _env("POSTGRES_DB", "ir_platform"),
        "USER": _env("POSTGRES_USER", "ir_platform"),
        "PASSWORD": _env("POSTGRES_PASSWORD", "ir_platform"),
        "HOST": _env("POSTGRES_HOST", "127.0.0.1"),
        "PORT": _env("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": int(_env("POSTGRES_CONN_MAX_AGE", "60")),
    },
    # Derived correlation store — the multi-host intrusion picture, kept apart from the
    # custody-sealed collection record so analysis cannot write to evidence and the two
    # scale independently. Defaults to a separate database on the same instance; point
    # CORRELATION_POSTGRES_HOST at another cluster to split it physically, no code change.
    "correlation": {
        "ENGINE": "ir_platform.vaultdb",
        "NAME": _env("CORRELATION_POSTGRES_DB", "ir_correlation"),
        "USER": _env("CORRELATION_POSTGRES_USER", _env("POSTGRES_USER", "ir_platform")),
        "PASSWORD": _env("CORRELATION_POSTGRES_PASSWORD", _env("POSTGRES_PASSWORD", "ir_platform")),
        "HOST": _env("CORRELATION_POSTGRES_HOST", _env("POSTGRES_HOST", "127.0.0.1")),
        "PORT": _env("CORRELATION_POSTGRES_PORT", _env("POSTGRES_PORT", "5432")),
        "CONN_MAX_AGE": int(_env("POSTGRES_CONN_MAX_AGE", "60")),
    },
    # Operational log store. Highest-volume writer in the platform and explicitly NOT
    # evidence, so it is kept out of the database that carries chain of custody: it must not
    # compete with collection for I/O, ride evidence backups, or inflate a case restore.
    "opslog": {
        "ENGINE": "ir_platform.vaultdb",
        "NAME": _env("OPSLOG_POSTGRES_DB", "ir_opslog"),
        "USER": _env("OPSLOG_POSTGRES_USER", _env("POSTGRES_USER", "ir_platform")),
        "PASSWORD": _env("OPSLOG_POSTGRES_PASSWORD", _env("POSTGRES_PASSWORD", "ir_platform")),
        "HOST": _env("OPSLOG_POSTGRES_HOST", _env("POSTGRES_HOST", "127.0.0.1")),
        "PORT": _env("OPSLOG_POSTGRES_PORT", _env("POSTGRES_PORT", "5432")),
        "CONN_MAX_AGE": int(_env("POSTGRES_CONN_MAX_AGE", "60")),
    },
}

DATABASE_ROUTERS = ["ir_platform.dbrouter.CorrelationRouter"]

REST_FRAMEWORK = {
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "cases.authentication.SSOHeaderAuthentication",   # oauth2-proxy/Keycloak SSO (browser)
        "rest_framework.authentication.TokenAuthentication",  # broker service account
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    # Every access refusal becomes an audit row (SRG-APP-000805-WSR-000140). Set here rather than in
    # each permission class: the next permission class added would not log, and the gap would be
    # found by needing the record and not having it.
    "EXCEPTION_HANDLER": "cases.denials.audited_exception_handler",
}

# --- SSO (oauth2-proxy → Keycloak OIDC) -----------------------------------------
# Shared secret nginx sets on requests it proxies to the backend; the SSO auth class
# only trusts the forwarded Remote-* identity when this matches (anti-spoofing).
SSO_PROXY_SECRET = _env("IR_SSO_PROXY_SECRET", "")

KEYCLOAK = {
    "URL": _env("KEYCLOAK_URL", "http://keycloak:8080"),
    "REALM": _env("KEYCLOAK_REALM", "irplatform"),
    "ADMIN_USER": _env("KC_BOOTSTRAP_ADMIN_USERNAME", _env("KEYCLOAK_ADMIN", "admin")),
    # KC_BOOTSTRAP_ADMIN_PASSWORD is the variable Keycloak itself honours, so it is the only
    # one guaranteed to match the account. Reading a second variable let the two diverge, and
    # user administration then failed with credentials that looked provisioned.
    "ADMIN_PASSWORD": _env("KC_BOOTSTRAP_ADMIN_PASSWORD", _env("KEYCLOAK_ADMIN_PASSWORD", "admin")),
}

# Demo role bootstrap (dev/UAT only): seed_roles creates one user per role with these
# passwords when set. Never set these in a real deployment — provision users properly.
SEED_DEMO_USERS = _bool("IR_SEED_DEMO_USERS", True)

# --- Celery / Redis ---------------------------------------------------------
CELERY_BROKER_URL = _env("CELERY_BROKER_URL", "redis://127.0.0.1:6379/0")
CELERY_RESULT_BACKEND = _env("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)
CELERY_TASK_TRACK_STARTED = True
# A memory analysis is acknowledged when it finishes, not when it is picked up, so a
# worker that dies mid-analysis does not lose the capture's place in the queue.
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1  # long memory-analysis tasks: fair dispatch.

# How long the broker waits for an acknowledgement before assuming the task was lost and handing
# it to another worker. This must exceed the longest task, and with Redis it silently does not:
# the default is one hour, while a Volatility pass over a real capture runs for well over that.
CELERY_BROKER_TRANSPORT_OPTIONS = {
    "visibility_timeout": int(_env("IR_VOL3_TIMEOUT", "10800")) + 3600,
}

# --- Object storage (MinIO local default, AWS S3 optional) ------------------
# Backend selection is purely which endpoint/creds are supplied; the code path is one.
OBJECT_STORE = {
    "ENDPOINT_URL": _env("S3_ENDPOINT_URL", "http://127.0.0.1:9000"),  # unset/None -> real AWS S3
    "ACCESS_KEY": _env("S3_ACCESS_KEY", "ir_platform"),
    "SECRET_KEY": _env("S3_SECRET_KEY", "ir_platform_secret"),
    "BUCKET": _env("S3_BUCKET", "ir-evidence"),
    "REGION": _env("S3_REGION", "us-east-1"),
    "USE_TLS": _bool("S3_USE_TLS", False),
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_TZ = True
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Application logs go to the console AND to a file, never to one or the other. The console
# copy is what `podman logs` shows while a container is alive; the file is what the shipper
# moves into object storage, which is the only copy that survives the container. An admin
# troubleshooting after the fact has nothing to read otherwise.
#
# The directory is created rather than assumed: a missing mount would make FileHandler raise
# at import and take the whole service down over a log path.
_LOG_DIR = _env("IR_APP_LOG_DIR", "/logs/app")
try:
    os.makedirs(_LOG_DIR, exist_ok=True)
    _LOG_FILE = os.path.join(_LOG_DIR, f"{_env('IR_LOG_NAME', 'backend')}-app.log")
    open(_LOG_FILE, "a").close()
except OSError:
    _LOG_FILE = ""

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "plain"},
        **({"file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": _LOG_FILE,
            # Bounded on disk: the shipper has already moved the bytes to object storage,
            # so the file is a buffer, not the archive.
            "maxBytes": 16 * 1024 * 1024,
            "backupCount": 2,
            "formatter": "plain",
        }} if _LOG_FILE else {}),
    },
    "root": {
        "handlers": ["console"] + (["file"] if _LOG_FILE else []),
        "level": _env("DJANGO_LOG_LEVEL", "INFO"),
    },
}

# Celery hijacks the root logger by default, which would send worker output around the
# handlers above and leave the worker's file empty.
CELERY_WORKER_HIJACK_ROOT_LOGGER = False
