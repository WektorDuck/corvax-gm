
FROM node:22-bookworm-slim

ENV NODE_ENV=production
ENV PORT=3001
ENV npm_config_build_from_source=true

WORKDIR /app/Website

# Инструменты для сборки SQLite и команда ps для concurrently
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 \
       make \
       g++ \
       procps \
    && rm -rf /var/lib/apt/lists/*

COPY Website/package.json Website/package-lock.json ./

# Собираем нативный модуль SQLite внутри этого контейнера
RUN npm ci --omit=dev --build-from-source \
    && npm cache clean --force

COPY Website/ ./
COPY Website/DataBase/database.db /app/seed/database.db

RUN mkdir -p /app/Website/DataBase \
    && chmod +x /app/Website/docker-entrypoint.sh

EXPOSE 3001

ENTRYPOINT ["/app/Website/docker-entrypoint.sh"]
