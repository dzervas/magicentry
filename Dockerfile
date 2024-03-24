FROM node:alpine as frontend

WORKDIR /usr/src/app

COPY static static
COPY *.js *.json ./
RUN npm install --dev
RUN npm run build

FROM rust:alpine as builder

RUN apk add --no-cache musl-dev

WORKDIR /usr/src/app

RUN cargo init --vcs none --bin
COPY Cargo.toml Cargo.lock ./
# Enable mount-type caching and dependency caching to be compatible with github actions
RUN cargo build --release && rm target/release/deps/magicentry*

COPY . .
RUN cargo build --release && cp target/release/magicentry .

# FROM gcr.io/distroless/cc-debian12
FROM alpine

COPY --from=builder /usr/src/app/magicentry /usr/local/bin/
COPY --from=frontend /usr/src/app/static /static

ENV CONFIG_FILE=/config.yaml
ENV RUST_LOG=info

EXPOSE 8080/tcp
CMD ["/usr/local/bin/magicentry"]

# TODO: Add healthcheck
