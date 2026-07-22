# ---- Build stage -----------------------------------------------------------
FROM rust:1.91-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies separately from source for faster rebuilds.
COPY Cargo.toml Cargo.lock ./
COPY crates/common/Cargo.toml crates/common/Cargo.toml
COPY crates/analyzer-basic/Cargo.toml crates/analyzer-basic/Cargo.toml
COPY crates/analyzer-llm/Cargo.toml crates/analyzer-llm/Cargo.toml
COPY crates/api/Cargo.toml crates/api/Cargo.toml
COPY crates/cli/Cargo.toml crates/cli/Cargo.toml

COPY crates/ crates/

# SQLX_OFFLINE=true: no database is needed at build time. The DB layer is
# optional at runtime too (see crates/common/src/database/mod.rs).
ENV SQLX_OFFLINE=true
RUN cargo build --release -p security-api

# ---- Runtime stage ----------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/security-api ./security-api
COPY crates/api/static ./crates/api/static

EXPOSE 3000

ENV RUST_LOG=info
CMD ["./security-api"]
