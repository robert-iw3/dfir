#!/usr/bin/env bash
# ==============================================================================
# Generate Django migrations against the SOURCE TREE.
#
# The backend image bakes the code in (`COPY backend/ .`), so running makemigrations in the
# deployed container writes a migration into a container filesystem that the next deploy
# discards — the model change then reaches production with no migration behind it, and the
# failure surfaces as a missing column far from the edit that caused it.
#
# So the image supplies Django and the source tree supplies the code: /app is mounted over.
#
#   ci/makemigrations.sh                 # all apps
#   ci/makemigrations.sh cases           # one app
#   ci/makemigrations.sh --check         # exit 1 if a model change has no migration
#
# No database is contacted; makemigrations reads models, not tables.
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"
RUNTIME="${IR_RUNTIME:-podman}"
IMAGE="${IR_BACKEND_IMAGE:-localhost/ir-backend:latest}"

${RUNTIME} image exists "${IMAGE}" 2>/dev/null || {
    printf '\033[1;31m✘\033[0m %s is not built — run deploy.sh enclave first\n' "${IMAGE}"
    exit 1
}

# Written back as the invoking user. Rootless podman maps the container's root to that user,
# so a migration generated here is owned by whoever ran it rather than by root.
${RUNTIME} run --rm \
    -v "${PLATFORM}/backend:/app:z" \
    -e DJANGO_SETTINGS_MODULE=ir_platform.settings \
    -e IR_SECRET_KEY=makemigrations-only \
    -e POSTGRES_HOST=127.0.0.1 \
    --network none \
    "${IMAGE}" python manage.py makemigrations "$@"
RC=$?

[[ ${RC} -eq 0 ]] \
    && printf '\n\033[1;32m✔\033[0m migrations are current in %s\n' "${PLATFORM#"${HOME}/"}/backend" \
    || printf '\n\033[1;31m✘\033[0m makemigrations exited %d\n' "${RC}"
exit ${RC}
