FROM rust:1.85-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked

FROM alpine:3.21
RUN apk add --no-cache libgcc
COPY --from=builder /app/target/release/dstore /usr/local/bin/dstore
ENTRYPOINT ["dstore"]
