# anpi

A lightweight uptime monitor written in Rust. One ~10 MB binary with an embedded SQLite database, a web panel, a public status page and alerts. A self-hostable alternative to Uptime Kuma that uses a few MB of RAM.

## Features

- **Monitors:** HTTP(S), TCP port, ping (ICMP), DNS and push (cron heartbeats).
- **IPv4 / IPv6 / auto per monitor.** Auto tries every address and records which one answered, so a broken IPv6 path shows up instead of hiding behind a fallback.
- **Response time broken into phases:** DNS, connect, TLS, server wait and transfer, with 24 h / 7 d / 30 d charts.
- **Noise control:** a monitor is marked down only after N failures in a row, and checks are retried at a shorter interval while failing.
- **Response checks:** status code ranges (`200-299, 301, 4xx`), keyword, regex, or a JSONPath value (`$.db.status == ok`).
- **Certificate expiry warnings** at the configured window, then at 7, 3 and 1 days before expiry.
- **Alerts** to Discord, Telegram, ntfy, e-mail (SMTP) or any JSON webhook. Each alert fires once per transition: down, back up, or certificate expiring.
- **Maintenance windows** suppress alerts.
- **Groups and sub-monitors.** Monitors can be grouped, and one monitor can sit under another, e.g. API endpoints under an "API" aggregate. The parent shows the worst status of its children.
- **Branding:** your own site name, logo (also used as the favicon) and public display names per monitor.
- **Public status page at `/`** with 30-day uptime bars and incidents, plus `/api/status.json`.
- **Live updates** over server-sent events.
- **Data retention:** raw checks for 24 h, then hourly roll-ups for a year. A few dozen monitors stay well under 100 MB.
- **Sign-in:** local accounts (argon2) or Keycloak / any OIDC provider. With OIDC enabled, only SSO sign-in is allowed.
- **Import** from an Uptime Kuma backup JSON.

## Quick start

### Docker

```sh
docker compose up -d
docker compose logs anpi | grep "setup code"
```

Open `http://localhost:3000/setup`, enter the setup code from the log and create the first account. The status page is at `/` and the panel at `/admin`.

### Binary + systemd

```sh
cargo build --release
sudo install -m 755 target/release/anpi /usr/local/bin/anpi
sudo useradd --system --no-create-home anpi
sudo install -D -m 600 deploy/anpi.env.example /etc/anpi/anpi.env   # edit it
sudo cp deploy/anpi.service /etc/systemd/system/
sudo systemctl enable --now anpi
journalctl -u anpi | grep "setup code"
```

The unit listens on `127.0.0.1:3000`; put a reverse proxy (Caddy, nginx) in front for HTTPS.

## Configuration

All configuration is through environment variables. Monitors, alerts and retention are managed in the panel.

| Variable | Default | |
|---|---|---|
| `ANPI_BIND` | `0.0.0.0:3000` | Listen address |
| `ANPI_DATA_DIR` | `./data` | Where `anpi.db` lives (`ANPI_DATABASE` overrides the file path) |
| `ANPI_BASE_URL` | – | Public URL, e.g. `https://status.example.com`. Required for OIDC; `https` enables secure cookies |
| `ANPI_TRUST_PROXY` | `false` | Use `X-Forwarded-For` for login rate limiting |
| `ANPI_MAX_CONCURRENT_CHECKS` | `64` | Upper bound on parallel checks |
| `ANPI_LOG` | `info` | Log filter (`debug`, `anpi=debug`, …) |
| `ANPI_OIDC_ISSUER` | – | e.g. `https://auth.example.com/realms/main`. Enables SSO-only mode |
| `ANPI_OIDC_CLIENT_ID` | – | |
| `ANPI_OIDC_CLIENT_SECRET` | – | Omit for public clients |
| `ANPI_OIDC_REQUIRED_ROLE` | – | Realm role, client role or group the user must have |
| `ANPI_OIDC_SCOPES` | `openid profile email` | |

### Keycloak

1. Create an OpenID Connect client `anpi` with **Client authentication** on and **Standard flow** enabled.
2. Set **Valid redirect URIs** to `https://status.example.com/auth/oidc/callback` and **Valid post logout redirect URIs** to `https://status.example.com/`.
3. Optional: create a realm role such as `monitoring`, assign it to people who may use the panel, and set `ANPI_OIDC_REQUIRED_ROLE=monitoring`. Client roles (`resource_access.anpi.roles`) and groups also work.

PKCE is always used. The ID token is validated for issuer, audience, expiry and nonce. It is fetched directly from the token endpoint over TLS (OIDC Core §3.1.3.7).

### Push monitors

The monitor page shows a URL such as:

```sh
curl -fsS "https://status.example.com/api/push/<token>?status=up&msg=OK&ping=1234"
```

If no push arrives within the interval, the monitor counts a failure. Send `status=down` to report one explicitly.

### Ping in Docker / systemd

ICMP needs either `CAP_NET_RAW` (granted in the systemd unit) or unprivileged ICMP sockets via `net.ipv4.ping_group_range`, which Docker enables by default.

## Command line

```sh
anpi                          # run the server
anpi healthcheck              # exit 0 if the local server is healthy (used by Docker)
anpi reset-password <user>    # reads a new password from stdin, signs out old sessions
```

## Development

```sh
cargo test     # unit + integration tests, all local, no network needed
cargo clippy --all-targets
```

The integration tests start real local servers (HTTP, self-signed HTTPS, a webhook receiver and a mock OIDC provider) and check:

- end-to-end alerting: exactly one down alert and one recovery, no alert during maintenance, no duplicate alert after a restart;
- the IPv4/IPv6 choice, TLS verification and certificate expiry, timeouts that name the failing phase;
- that retention never changes uptime numbers;
- CSRF, origin checks, login rate limiting, session invalidation;
- the OIDC flow, including state binding, nonce, PKCE and required roles.

## Layout

```
src/checks      HTTP client with phase timings, TCP, ping, DNS, content rules
src/monitor     scheduler, state machine, SSL warning steps, batched writer
src/notify.rs   alert channels
src/retention.rs, src/stats.rs   roll-ups and reads across raw + hourly data
src/auth        passwords, rate limiting, OIDC
src/web         axum handlers, SVG charts, templates in /templates, assets in /static
```
