FROM --platform=$BUILDPLATFORM node:alpine AS frontend

WORKDIR /usr/src/app

COPY static static
COPY *.js *.json ./
RUN npm install --include=dev
RUN npm run build

FROM --platform=$BUILDPLATFORM rust AS builder

WORKDIR /usr/src/app

ARG TARGETPLATFORM
RUN echo $(test "$TARGETPLATFORM" = "linux/arm64" && echo aarch64-unknown-linux-gnu || echo x86_64-unknown-linux-gnu) > /.target-triplet
RUN rustup target add $(cat /.target-triplet)

RUN test "$TARGETPLATFORM" = "linux/arm64" || exit 0 && apt-get update && apt-get install -y gcc-aarch64-linux-gnu && apt-get clean

RUN cargo init --vcs none --bin
COPY Cargo.toml Cargo.lock .
COPY .cargo .cargo

# Enable mount-type caching and dependency caching to be compatible with github actions
ARG FEATURES="default"
RUN cargo build --release --features=$FEATURES --target $(cat /.target-triplet) && rm target/$(cat /.target-triplet)/release/deps/magicentry*

COPY . .
RUN cargo build --release --features=$FEATURES --target $(cat /.target-triplet) && cp target/$(cat /.target-triplet)/release/magicentry .

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /usr/src/app/magicentry /usr/local/bin/
COPY --from=frontend /usr/src/app/static /static

ENV CONFIG_FILE=/config.yaml
ENV RUST_LOG=info

EXPOSE 8080/tcp
CMD ["/usr/local/bin/magicentry"]

# TODO: Add healthcheck
