# Single-service build. Shared proto/common are git dependencies pinned by tag,
# fetched by cargo, so the build context is just this repo.
FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --bin auth-service

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/auth-service /usr/local/bin/app
ENTRYPOINT ["app"]
