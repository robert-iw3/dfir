# Frontend image.
FROM docker.io/library/node:lts-slim@sha256:235600a8101ab264e117b1768e925532262668dc9b581ef1dd7d96ced463b8e7 AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build \
    && test -f /app/dist/index.html   # build smoke test: SPA actually emitted

FROM docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache nginx curl gettext \
    && mkdir -p /usr/share/nginx/html /run/nginx /etc/nginx/templates
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Build-time smoke tests so a broken image never ships: the SPA bundle exists and the rendered
# nginx config parses. The temp hosts entry lets `nginx -t` resolve the `backend` upstream during
# build (real DNS at run).
RUN test -f /usr/share/nginx/html/index.html \
    && test -d /usr/share/nginx/html/assets \
    && IR_SSO_PROXY_SECRET="" NGINX_RESOLVER="127.0.0.11" \
       envsubst '${IR_SSO_PROXY_SECRET} ${NGINX_RESOLVER}' \
         < /etc/nginx/templates/default.conf.template > /etc/nginx/http.d/default.conf \
    && echo "127.0.0.1 backend" >> /etc/hosts \
    && nginx -t -c /etc/nginx/nginx.conf

EXPOSE 8080
ENTRYPOINT ["/docker-entrypoint.sh"]
