FROM rust:alpine as builder

# RUN cargo install cargo-build-dependencies && cargo new --bin /usr/src/app
RUN apk add --no-cache musl-dev

WORKDIR /usr/src/app
# COPY Cargo.toml Cargo.lock ./
# RUN cargo build-dependencies --release

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/git,id=just-passwordless-cargo-git-cache \
	--mount=type=cache,target=/usr/local/cargo/registry,id=just-passwordless-cargo-registry-cache \
	--mount=type=cache,target=/usr/src/app/target,id=just-passwordless-cargo-target-cache \
	cargo build --release && cp target/release/just-passwordless .

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /usr/src/app/just-passwordless /usr/local/bin/

ENV CONFIG_FILE=/config.yaml
ENV RUST_LOG=info

EXPOSE 8080/tcp
CMD ["/usr/local/bin/just-passwordless"]
