FROM docker.io/library/rust:1.93-bookworm AS builder
WORKDIR /src
COPY backend /src/backend
RUN cd /src/backend && cargo build --release

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl nginx default-mysql-client && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /src/backend/target/release/ezkey-backend /app/ezkey-backend
COPY web /app/web
COPY addons /app/addons
COPY deploy/nginx/ezkey.conf /etc/nginx/conf.d/default.conf
COPY scripts/entrypoint-ezkey.sh /entrypoint-ezkey.sh
EXPOSE 8081
CMD ["/entrypoint-ezkey.sh"]
