FROM --platform=$BUILDPLATFORM rust:1 AS builder
WORKDIR /app

RUN apt-get update && apt-get install --no-install-recommends -y npm && apt-get clean

ARG TARGETPLATFORM
RUN echo $(test "$TARGETPLATFORM" = "linux/arm64" && echo aarch64-unknown-linux-gnu || echo x86_64-unknown-linux-gnu) > /.target-triplet
RUN --mount=type=cache,target=/app/target/ \
	--mount=type=cache,target=/usr/local/cargo/git/db/ \
	--mount=type=cache,target=/usr/local/cargo/registry/cache/ \
	rustup target add $(cat /.target-triplet)

RUN test "$TARGETPLATFORM" = "linux/arm64" || exit 0 && apt-get update && apt-get install -y gcc-aarch64-linux-gnu && apt-get clean
# For libxml2 install: make pkg-config libclang-dev libssl-dev libxml2-dev libfindbin-libs-perl
# For arm64 also do: dpkg --add-architecture arm64 && apt-get update && apt-get install -y libxml2-dev:arm64
#     during cargo build the following env is also required: PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig/:$PKG_CONFIG_PATH PKG_CONFIG_SYSROOT_DIR=/

COPY package.json .
COPY package-lock.json .
RUN npm ci

COPY . .

ARG FEATURES="default"
RUN --mount=type=cache,target=/app/target/ \
	--mount=type=cache,target=/usr/local/cargo/git/db/ \
	--mount=type=cache,target=/usr/local/cargo/registry/cache/ \
	cargo build --release --features=$FEATURES --target $(cat /.target-triplet) && cp target/$(cat /.target-triplet)/release/magicentry .

FROM gcr.io/distroless/cc-debian13

COPY --from=builder /app/magicentry /usr/local/bin/
COPY --from=builder /app/static /static

ENV CONFIG_FILE=/config.yaml
ENV RUST_LOG=info

EXPOSE 8080/tcp
CMD ["/usr/local/bin/magicentry"]

# TODO: Add healthcheck
