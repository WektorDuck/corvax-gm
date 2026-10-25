
FROM node:22-bookworm-slim

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app/Website

COPY Website/package.json Website/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY Website/ ./
COPY Website/DataBase/database.db /app/seed/database.db

RUN mkdir -p /app/Website/DataBase \
    && chmod +x /app/Website/docker-entrypoint.sh

EXPOSE 3000

ENTRYPOINT ["/app/Website/docker-entrypoint.sh"]