# Repository Guidelines

## Project Structure & Module Organization

- Source: `src/` (Actix-web server, domains like `oidc/`, `saml/`, `webauthn/`, `secret/`). Entry points: `src/main.rs` (binary), `src/lib.rs` (shared code).
- Tests: unit/integration under `src/tests/` and inline `#[cfg(test)]` modules.
- Assets: `static/` (Handlebars templates in `static/templates/`, CSS built to `static/main.build.css`).
- E2E specs: `hurl/*.hurl` (HTTP flows).
- Docs: `docs/` (published), `new-docs/` (Astro site WIP).
- Config samples: `config.sample.yaml`, `users.sample.yaml`.

## Build, Test, and Development Commands

- Build server: `cargo build` (add `--release` for production).
- Frontend assets: `yarn build` (webpack + Tailwind 4 → `static/main.build.css`).
- Unit/integration tests: `cargo test --features kube` or `yarn test-server`.
- End‑to‑end: `yarn test` (requires `hurl` and server at `:8080`).
- Dev loop: `yarn start` (watches Rust, assets, and e2e fixtures).
- Optional dev shell: `nix develop` (provides Rust toolchain, hurl, yarn, sqlx-cli).

## Coding Style & Naming Conventions

- Formatting: rustfmt with hard tabs (`.rustfmt.toml`). Run `cargo fmt`.
- Lints: `unsafe_code = forbid`; Clippy `pedantic`/`nursery` denied; avoid `unwrap`. Run `cargo clippy --all-features`.
- Naming: files/modules `snake_case`; types/traits `CamelCase`; constants `UPPER_SNAKE_CASE`.

## Testing Guidelines

- Place scenario tests in `src/tests/` (e.g., `flow_scoped.rs`); name functions `test_*`.
- Add table‑driven unit tests near code for small utilities.
- E2E flows live in `hurl/`; run with `yarn test-e2e`. Keep them deterministic and single‑job.

## Commit & Pull Request Guidelines

- Commits: imperative mood, concise scope (e.g., "feat(oidc): validate PKCE").
- PRs: include summary, rationale, and screenshots for UI/template changes. Link issues.
- Checks: ensure `cargo build`, `yarn build`, `cargo clippy`, and tests pass locally.

## Security & Configuration Tips

- Start from `config.sample.yaml`; do not commit secrets. Use `DATABASE_URL` (sqlite by default via `flake.nix`).
- Prefer `sqlx` queries with compile‑time checks; validate external inputs at boundaries.
- Keep templates free of sensitive data; log at appropriate levels (`RUST_LOG`).
