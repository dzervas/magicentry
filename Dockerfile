FROM --platform=$BUILDPLATFORM node:alpine AS frontend

WORKDIR /usr/src/app

COPY static static
COPY *.js *.json ./
RUN npm ci
RUN npm run build

FROM --platform=$BUILDPLATFORM rust:1 AS builder
WORKDIR /app

ARG TARGETPLATFORM
RUN echo $(test "$TARGETPLATFORM" = "linux/arm64" && echo aarch64-unknown-linux-gnu || echo x86_64-unknown-linux-gnu) > /.target-triplet
RUN --mount=type=cache,target=/app/target/ \
	--mount=type=cache,target=/usr/local/cargo/git/db/ \
	--mount=type=cache,target=/usr/local/cargo/registry/ \
	rustup target add $(cat /.target-triplet)

RUN test "$TARGETPLATFORM" = "linux/arm64" || exit 0 && apt-get update && apt-get install -y gcc-aarch64-linux-gnu && apt-get clean

COPY . .

ARG FEATURES="default"
RUN --mount=type=cache,target=/app/target/ \
	--mount=type=cache,target=/usr/local/cargo/git/db/ \
	--mount=type=cache,target=/usr/local/cargo/registry/ \
	cargo build --release --features=$FEATURES --target $(cat /.target-triplet) && cp target/$(cat /.target-triplet)/release/magicentry .

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /app/magicentry /usr/local/bin/
COPY --from=frontend /usr/src/app/static /static

ENV CONFIG_FILE=/config.yaml
ENV RUST_LOG=info

EXPOSE 8080/tcp
CMD ["/usr/local/bin/magicentry"]

# TODO: Add healthcheck
