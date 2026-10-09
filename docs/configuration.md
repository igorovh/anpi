# Configuration and deployment

[← Back to the README](../README.md)

## Environment variables

| Variable | Default | |
|---|---|---|
| `ANPI_BIND` | `0.0.0.0:3000` | Listen address |
| `ANPI_DATA_DIR` | `./data` | Directory for `anpi.db` (`ANPI_DATABASE` sets the file path directly) |
| `ANPI_BASE_URL` | – | Public URL, e.g. `https://status.example.com`. Used for links and SSO; `https` turns on secure cookies |
| `ANPI_TRUST_PROXY` | `false` | Behind a reverse proxy, take the client address for login rate limiting from the **last** `X-Forwarded-For` entry. Enable it only when a proxy always appends that entry (nginx `$proxy_add_x_forwarded_for`, Caddy and Traefik do); without a proxy, clients could set it themselves |
| `ANPI_MAX_CONCURRENT_CHECKS` | `64` | Upper bound on checks running at once |
| `ANPI_LOG` | `info` | Log filter, e.g. `debug` or `anpi=debug` |
| `ANPI_OIDC_ISSUER`, `ANPI_OIDC_CLIENT_ID`, `ANPI_OIDC_CLIENT_SECRET` | – | SSO from the environment; overrides the panel |
| `ANPI_OIDC_REQUIRED_ROLE`, `ANPI_OIDC_SCOPES` | –, `openid profile email` | |

Everything else is set in the panel.

## Sign-in and SSO

The first account is created with the setup code from the log. More password accounts can be added under **Settings → Users**.

Single sign-on works with Keycloak or any OpenID Connect provider. You can set it under **Settings → Single sign-on** (public URL, issuer, client ID and secret, an optional required role or group) or with environment variables, which take precedence. With SSO on, password sign-in is turned off. The panel will not turn SSO on unless the provider answers, and `anpi disable-sso` on the server turns it off again if you get locked out.

For Keycloak:

1. Create an OpenID Connect client with **Client authentication** and **Standard flow** enabled.
2. Set **Valid redirect URIs** to `https://status.example.com/auth/oidc/callback` and **Valid post logout redirect URIs** to `https://status.example.com/`.
3. Optional: require a realm role, client role or group, for example `monitoring`.

PKCE is always used. The ID token's issuer, audience, expiry and nonce are checked, and the login state is bound to the browser that started it.

## Backup and moving servers

**Settings → Backup → Export configuration** downloads one JSON file. It contains monitors with their sub-monitors, groups, notification channels, maintenance windows, settings, the logo and SSO settings. Check history and user accounts are left out. The file holds webhook URLs, passwords and secrets, so keep it private.

**Import** accepts that file or an Uptime Kuma backup and detects which one it is.
- *Add* keeps what is already there and reuses groups and channels with the same name.
- *Replace* deletes the current monitors with their history, groups, channels and maintenance windows first, after an explicit confirmation.
- Push tokens are kept, so cron jobs keep working after a move.
- Imported SSO settings stay off until you enable them.

The same works offline with `anpi export` and `anpi import`.

## Data and retention

Checks are stored for 24 hours, then rolled up into hourly averages kept for a year; closed incidents are kept for a year. All three periods can be changed under **Settings**. Uptime figures and charts read across raw and hourly data, so pruning never changes them. A few dozen monitors stay well under 100 MB, and the current database size is shown in the settings.

## Deployment notes

- **systemd:** copy the binary to `/usr/local/bin/anpi`; `deploy/anpi.service` runs anpi as an unprivileged user with a hardened sandbox; `deploy/anpi.env.example` lists the settings.
- **Reverse proxy:** put Caddy or nginx in front for HTTPS and set `ANPI_TRUST_PROXY=true`.
- **IPv6 in Docker:** IPv6 monitors need IPv6 inside the container. Enable it in the Docker daemon or use `network_mode: host`.
- **Ping:** ICMP needs `CAP_NET_RAW` (granted in the systemd unit) or unprivileged ICMP sockets through `net.ipv4.ping_group_range`, which Docker allows by default.

## Command line

```sh
anpi                          # run the server
anpi demo                     # fill an empty database with example data
anpi healthcheck              # exit 0 if the local server is healthy (used by Docker)
anpi reset-password <user>    # set a new password from stdin and sign out old sessions
anpi disable-sso              # turn off SSO configured in the panel
anpi export [file]            # write the configuration as JSON (stdout by default)
anpi import <file> [--replace]  # load an anpi export or an Uptime Kuma backup
```

## Security notes

- **Everyone who can sign in is an admin.** Admins can make anpi send requests to any address, including the local network (monitors, *Run check now*, webhooks and SSO tests), and monitored services can redirect HTTP checks elsewhere. That is what a monitor needs to do, so only give accounts to people you trust with that.
- **SSO without a required role** lets every account the identity provider signs in become an admin. The settings page warns about this; set a role or group unless the realm is yours alone.
- **Sign-in is rate limited** per client address (10 failures per 15 minutes) and password hashing runs off the request threads with a small concurrency limit, so floods of sign-in attempts cannot stall the checks.
- **Alerts quote monitored responses** in some messages (for example a JSON value that did not match). Discord messages are escaped and send no mentions.
