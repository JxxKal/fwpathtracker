FROM node:22-alpine AS build

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
# nginx.conf wird zur Laufzeit vom Entrypoint generiert (HTTP/HTTPS je nach
# /certs). Die statische Datei bleibt nur als Referenz im Repo.
COPY --from=build /app/dist /usr/share/nginx/html
COPY docker-entrypoint.sh /docker-entrypoint-fwpt.sh
RUN chmod +x /docker-entrypoint-fwpt.sh
EXPOSE 80 443
ENTRYPOINT ["/docker-entrypoint-fwpt.sh"]
