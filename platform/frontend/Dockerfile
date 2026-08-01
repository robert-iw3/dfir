# Frontend image.
FROM docker.io/library/node:lts-slim AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build \
    && test -f /app/dist/index.html   # build smoke test: SPA actually emitted

FROM docker.io/library/alpine:3.24
RUN apk add --no-cache nginx curl gettext \
    && mkdir -p /usr/share/nginx/html /run/nginx /etc/nginx/templates
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Smoke tests — verified at build time, so a broken image never ships:
#   1. the SPA bundle is present, 2. the rendered nginx config parses. The temp hosts
#   entry lets `nginx -t` resolve the `backend` upstream during the build (real DNS at run).
RUN test -f /usr/share/nginx/html/index.html \
    && test -d /usr/share/nginx/html/assets \
    && IR_SSO_PROXY_SECRET="" NGINX_RESOLVER="127.0.0.11" \
       envsubst '${IR_SSO_PROXY_SECRET} ${NGINX_RESOLVER}' \
         < /etc/nginx/templates/default.conf.template > /etc/nginx/http.d/default.conf \
    && echo "127.0.0.1 backend" >> /etc/hosts \
    && nginx -t -c /etc/nginx/nginx.conf

EXPOSE 8080
ENTRYPOINT ["/docker-entrypoint.sh"]
