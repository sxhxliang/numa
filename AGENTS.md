# Repository Guidelines

## Project Structure & Module Organization
`src/` contains the Rust crate: `main.rs` is the CLI/service entry point and `lib.rs` wires feature modules such as `api`, `serve`, `recursive`, `doh`, `dot`, and platform-specific `windows_service`. Keep new runtime code in focused modules under `src/` and expose them through `lib.rs` only when needed across the crate.

`tests/` holds regression and integration coverage. Use Rust tests for targeted behavior (`tests/soa_compression_bug.rs`) and shell or Docker scripts for end-to-end flows (`tests/integration.sh`, `tests/docker/`). Benchmarks live in `benches/` and supporting benchmark assets in `bench/`. Docs and static site content live under `blog/`, `site/`, `recipes/`, and `assets/`.

## Build, Test, and Development Commands
Use Cargo directly or the equivalent `Makefile` targets:

- `cargo build` or `make build`: compile the crate.
- `cargo test` or `make test`: run unit and integration tests wired through Cargo.
- `cargo clippy -- -D warnings` or `make check`: fail on lint warnings.
- `cargo fmt --check` or `make fmt`: verify formatting.
- `cargo audit` or `make audit`: scan dependencies.
- `cargo bench` or `make bench`: run Criterion benchmarks.
- `./tests/integration.sh`: run the main local integration suite.

## Coding Style & Naming Conventions
Follow Rust 2021 defaults: 4-space indentation, `snake_case` for functions/modules, `CamelCase` for types, and `SCREAMING_SNAKE_CASE` for constants. Keep modules small and responsibility-driven; this crate favors explicit feature files over deeply nested directories. Run `cargo fmt` before opening a PR and treat `clippy` warnings as errors.

## Testing Guidelines
Add unit tests beside implementation when logic is local, and add cross-module or platform-sensitive coverage under `tests/`. Name regression tests after the bug or behavior they protect. If a change affects install flows, DNS transports, or platform integration, run the relevant shell/Docker script in `tests/` and mention the command in the PR.

## Commit & Pull Request Guidelines
Recent history uses Conventional Commit-style prefixes such as `fix(windows): ...` and `refactor(windows): ...`. Keep commit subjects imperative and scoped when helpful. PRs should explain user-visible impact, list validation performed, link the issue when applicable, and include screenshots only for dashboard or site changes.

## Security & Configuration Tips
Do not commit local secrets or machine-specific configs. Use `numa.toml` as the reference config, and test privileged install/service changes carefully because they modify system DNS and service state.
