# Static web image: marketing site + admin/dashboard SPA.
# Build context: repository root after homepage/ is copied from respire-site.
#   docker build -f deploy/web/Dockerfile -t respire-web:develop .

FROM node:22-bookworm-slim AS homepage
WORKDIR /src
COPY homepage/package.json homepage/package-lock.json /src/homepage/
WORKDIR /src/homepage
RUN npm ci
COPY homepage/ /src/homepage/
RUN npm run build \
    && test -f /src/site/dist/client/index.html \
    && test -f /src/site/dist/client/zh/index.html

FROM node:22-bookworm-slim AS admin-ui
WORKDIR /ui
COPY admin-ui/package.json admin-ui/package-lock.json ./
RUN npm ci
COPY admin-ui/ ./
RUN npm run build \
    && test -f /ui/dist/index.html

FROM nginx:1.27-alpine
RUN apk add --no-cache wget
COPY --from=homepage /src/site/dist/client /usr/share/nginx/html
COPY --from=admin-ui /ui/dist/index.html /usr/share/nginx/html/admin.html
COPY deploy/web/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
