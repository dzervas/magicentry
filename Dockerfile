FROM node:alpine as frontend

WORKDIR /usr/src/app

COPY static static
COPY *.js *.json ./
RUN npm install --dev
RUN npm run build

FROM rust:alpine as builder

# RUN cargo install cargo-build-dependencies && cargo new --bin /usr/src/app
RUN apk add --no-cache musl-dev

WORKDIR /usr/src/app

RUN cargo init --bin
COPY Cargo.toml Cargo.lock ./
# Enable mount-type caching and dependency caching to be compatible with github actions
RUN --mount=type=cache,target=/usr/local/cargo/git,id=just-passwordless-cargo-git-cache \
	--mount=type=cache,target=/usr/local/cargo/registry,id=just-passwordless-cargo-registry-cache \
	--mount=type=cache,target=/usr/src/app/target,id=just-passwordless-cargo-target-cache \
	cargo build --release

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/git,id=just-passwordless-cargo-git-cache \
	--mount=type=cache,target=/usr/local/cargo/registry,id=just-passwordless-cargo-registry-cache \
	--mount=type=cache,target=/usr/src/app/target,id=just-passwordless-cargo-target-cache \
	rm target/release/deps/just_passwordless* && \
	cargo build --release && \
	cp target/release/just-passwordless .

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /usr/src/app/just-passwordless /usr/local/bin/
COPY --from=frontend /usr/src/app/static /static

ENV CONFIG_FILE=/config.yaml
ENV RUST_LOG=info

EXPOSE 8080/tcp
CMD ["/usr/local/bin/just-passwordless"]

# TODO: Add healthcheck
