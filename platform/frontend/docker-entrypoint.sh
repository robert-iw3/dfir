#!/bin/sh
# Render the nginx config from its template (injecting IR_SSO_PROXY_SECRET at runtime),
# then start nginx. Only the whitelisted var is substituted so nginx's own $variables survive.
set -e
export IR_SSO_PROXY_SECRET="${IR_SSO_PROXY_SECRET:-}"
# nginx needs an explicit resolver address to re-resolve upstreams at request time.
# Take whatever the container runtime configured rather than hardcoding one: podman,
# Docker and a split-tier deployment all use different addresses.
NGINX_RESOLVER="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf)"
: "${NGINX_RESOLVER:=127.0.0.11}"
export NGINX_RESOLVER

envsubst '${IR_SSO_PROXY_SECRET} ${NGINX_RESOLVER}' \
    < /etc/nginx/templates/default.conf.template \
    > /etc/nginx/http.d/default.conf
exec nginx -g 'daemon off;'
