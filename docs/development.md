# Development

[← Back to the README](../README.md)

## Example data

```sh
ANPI_DATA_DIR=/tmp/anpi-demo anpi demo   # groups, sub-monitors and 30 days of history
ANPI_DATA_DIR=/tmp/anpi-demo anpi
```

The public status page is at `/` and the panel at `/admin`.

## Running locally

Use a debug build (`cargo run`) while working on anpi; `cargo build --release` takes minutes because of full LTO. Debug builds read `static/` from disk on every request, so CSS and JS edits only need a page reload. Templates in `templates/` are compiled in, so they need `cargo run` again, which is incremental and quick. Dependencies are compiled with optimisations once, so the debug server runs at close to release speed.

## Tests and layout

```sh
cargo test                    # unit and integration tests; everything runs locally
cargo clippy --all-targets
```

The integration tests start real local servers (HTTP, self-signed HTTPS, a WebSocket echo server, a webhook receiver and a mock OIDC provider). They check that each outage produces exactly one down and one recovery alert, that maintenance and restarts stay quiet, IPv4/IPv6 selection, TLS and certificate handling, retention, CSRF and origin checks, login rate limiting, drag and drop moves and the full SSO flow.

`docs/brand/*.html` are the sources of the README images, and `anpi demo` produces the data shown in the screenshots.

Releases are built by `.github/workflows/release.yml` when a `v*` tag is pushed. The workflow builds the archives, publishes the GitHub release, and assembles the Docker image from the same static binaries using `Dockerfile.release`.

```
src/checks      HTTP client with phase timings, WebSocket, TCP, ping, DNS, response rules
src/monitor     scheduler, state machine, certificate warnings, batched writer
src/notify.rs   alert channels
src/stats.rs    reads across raw and hourly data; src/retention.rs rolls up and prunes
src/auth        passwords, rate limiting, OIDC, SSO settings
src/web         axum handlers and SVG charts; HTML in templates/, CSS and JS in static/
```
