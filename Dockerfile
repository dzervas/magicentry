FROM --platform=$BUILDPLATFORM node:alpine AS frontend

WORKDIR /usr/src/app

COPY static static
COPY *.js *.json ./
RUN npm install --include=dev
RUN npm run build

FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM --platform=$BUILDPLATFORM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

ARG TARGETPLATFORM
RUN echo $(test "$TARGETPLATFORM" = "linux/arm64" && echo aarch64-unknown-linux-gnu || echo x86_64-unknown-linux-gnu) > /.target-triplet
RUN rustup target add $(cat /.target-triplet)

RUN test "$TARGETPLATFORM" = "linux/arm64" || exit 0 && apt-get update && apt-get install -y gcc-aarch64-linux-gnu && apt-get clean

ARG FEATURES="default"
RUN cargo chef cook --release --features=$FEATURES --target $(cat /.target-triplet) --recipe-path recipe.json

# Enable mount-type caching and dependency caching to be compatible with github actions
COPY . .
RUN cargo build --release --features=$FEATURES --target $(cat /.target-triplet) && cp target/$(cat /.target-triplet)/release/magicentry .

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /app/magicentry /usr/local/bin/
COPY --from=frontend /usr/src/app/static /static

ENV CONFIG_FILE=/config.yaml
ENV RUST_LOG=info

EXPOSE 8080/tcp
CMD ["/usr/local/bin/magicentry"]

# TODO: Add healthcheck
