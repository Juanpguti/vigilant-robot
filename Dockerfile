# ---- Etapa 1: dependencias de producción ----
FROM node:22-alpine AS deps
WORKDIR /app
COPY app/package*.json ./
RUN npm ci --omit=dev

# ---- Etapa 2: imagen final mínima ----
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app

RUN addgroup -S app && adduser -S app -G app \
  # La app solo necesita el runtime de Node: se eliminan los gestores de paquetes
  # que trae la imagen base (npm, npx, corepack, yarn). Reducen superficie de
  # ataque y arrastran dependencias propias con CVEs (tar, sigstore, picomatch...).
  && rm -rf /usr/local/lib/node_modules \
            /usr/local/bin/npm /usr/local/bin/npx \
            /usr/local/bin/corepack \
            /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-*

COPY --from=deps /app/node_modules ./node_modules
COPY app/src ./src
COPY app/package.json ./

USER app
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/health || exit 1

CMD ["node", "src/index.js"]
