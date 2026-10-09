# Configuration and deployment

[← Back to the README](../README.md)

## Environment variables

| Variable | Default | |
|---|---|---|
| `ANPI_BIND` | `0.0.0.0:3000` | Listen address |
| `ANPI_DATA_DIR` | `./data` | Directory for `anpi.db` (`ANPI_DATABASE` sets the file path directly) |
| `ANPI_BASE_URL` | – | Public URL, e.g. `https://status.example.com`. Used for links and SSO; `https` turns on secure cookies |
| `ANPI_TRUST_PROXY` | `false` | Behind a reverse proxy, take the client address for login rate limiting from the **last** `X-Forwarded-For` entry. Enable it only when a proxy always appends that entry (nginx `$proxy_add_x_forwarded_for`, Caddy and Traefik do); without a proxy, clients could set it themselves |
| `ANPI_CLIENT_IP_HEADER` | – | Take the client address from this header instead, e.g. `CF-Connecting-IP` behind Cloudflare. Only safe when the firewall lets nothing but the proxy reach anpi |
| `ANPI_TLS_CERT`, `ANPI_TLS_KEY` | – | PEM certificate and key; anpi then serves HTTPS itself, without a reverse proxy |
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

**Import** restores that file:
- *Add* keeps what is already there and reuses groups and channels with the same name.
- *Replace* deletes the current monitors with their history, groups, channels and maintenance windows first, after an explicit confirmation.
- Push tokens are kept, so cron jobs keep working after a move.
- Imported SSO settings stay off until you enable them.

The same works offline with `anpi export` and `anpi import`.

## Data and retention

Checks are stored for 24 hours, then rolled up into hourly averages kept for a year; closed incidents are kept for a year. All three periods can be changed under **Settings**. Uptime figures and charts read across raw and hourly data, so pruning never changes them. A few dozen monitors stay well under 100 MB, and the current database size is shown in the settings.

## IPv6-only server behind Cloudflare

anpi can run on a small IPv6-only VPS with Cloudflare in front, without a reverse proxy or tunnel.

**1. Reach IPv4-only services.** GitHub, Discord and many monitored sites have no IPv6 address. Use a DNS64/NAT64 service, for example the free one at [nat64.net](https://nat64.net), or one from your provider. With systemd-resolved:

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNS=2a00:1098:2b::1 2a01:4f8:c2c:123f::1 2a00:1098:2c::1\nDomains=~.\n' | sudo tee /etc/systemd/resolved.conf.d/nat64.conf
sudo systemctl restart systemd-resolved
curl -sI https://github.com | head -1   # should print HTTP/2 200
```

Monitors of IPv4-only sites and Discord alerts go through that gateway, so they depend on it staying up.

**2. Install anpi** with the systemd unit from the release archive:

```sh
V=v0.2.1
case $(dpkg --print-architecture) in amd64) T=x86_64-unknown-linux-musl;; arm64) T=aarch64-unknown-linux-musl;; esac
cd /tmp
curl -fLO https://github.com/igorovh/anpi/releases/download/$V/anpi-$V-$T.tar.gz
curl -fLO https://github.com/igorovh/anpi/releases/download/$V/anpi-$V-$T.tar.gz.sha256
sha256sum -c anpi-$V-$T.tar.gz.sha256 && tar xzf anpi-$V-$T.tar.gz
sudo install -m 755 anpi-$V-$T/anpi /usr/local/bin/anpi
sudo useradd --system --no-create-home --shell /usr/sbin/nologin anpi
sudo install -d -m 755 /etc/anpi
sudo install -m 600 -o anpi anpi-$V-$T/deploy/anpi.env.example /etc/anpi/anpi.env
sudo cp anpi-$V-$T/deploy/anpi.service /etc/systemd/system/ && sudo systemctl daemon-reload
```

**3. Cloudflare.** Add a proxied `AAAA` record for the status page, set **SSL/TLS** to **Full (strict)** and create an **Origin Server** certificate. Save it as `/etc/anpi/origin.pem` and the key as `/etc/anpi/origin.key`, readable by the `anpi` user only:

```sh
sudo chown anpi:anpi /etc/anpi/origin.*; sudo chmod 600 /etc/anpi/origin.key
```

**4. Configure** `/etc/anpi/anpi.env`:

```sh
ANPI_BIND=[::]:443
ANPI_BASE_URL=https://status.example.com
ANPI_TLS_CERT=/etc/anpi/origin.pem
ANPI_TLS_KEY=/etc/anpi/origin.key
ANPI_CLIENT_IP_HEADER=CF-Connecting-IP
```

The unit allows binding port 443. Start anpi with `sudo systemctl enable --now anpi`, read the setup code with `sudo journalctl -u anpi | grep "setup code"` and open `https://status.example.com/setup`.

**5. Firewall.** Let only Cloudflare reach port 443; otherwise anyone could bypass it and fake `CF-Connecting-IP`. With nftables (check the ranges at [cloudflare.com/ips-v6](https://www.cloudflare.com/ips-v6) and keep console access in case SSH gets locked out):

```
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    meta l4proto ipv6-icmp accept
    tcp dport 22 accept
    tcp dport 443 ip6 saddr { 2400:cb00::/32, 2606:4700::/32, 2803:f800::/32, 2405:b500::/32, 2405:8100::/32, 2a06:98c0::/29, 2c0f:f248::/32 } accept
  }
}
```

Save it as `/etc/nftables.conf` and run `sudo systemctl enable --now nftables`.

## Deployment notes

- **systemd:** copy the binary to `/usr/local/bin/anpi`; `deploy/anpi.service` runs anpi as an unprivileged user with a hardened sandbox; `deploy/anpi.env.example` lists the settings.
- **Reverse proxy:** put Caddy or nginx in front for HTTPS and set `ANPI_TRUST_PROXY=true`.
- **IPv6 in Docker:** IPv6 monitors need IPv6 inside the container. Enable it in the Docker daemon or use `network_mode: host`.
- **Ping:** ICMP needs `CAP_NET_RAW` (granted in the systemd unit) or unprivileged ICMP sockets through `net.ipv4.ping_group_range`, which Docker allows by default.

## Updating

**Binary (Linux, macOS on Apple Silicon):** `sudo anpi update` downloads the newest release from GitHub, checks its SHA-256, swaps the binary and restarts `anpi.service`.
- `anpi update --check` only reports whether a newer version exists.
- `--version 0.2.0` installs a specific release; `--no-restart` leaves the restart to you.
- The replaced binary stays next to the new one as `anpi.old`; `sudo anpi update --rollback` puts it back.
- Before a new version changes the database schema, anpi copies the database to `anpi.db.before-<version>`. After rolling back across such a change, restore that copy too.

**Docker:** `docker compose pull && docker compose up -d`. Pin a tag such as `ghcr.io/igorovh/anpi:0.1` to get fixes without larger changes.

## Command line

```sh
anpi                          # run the server
anpi demo                     # fill an empty database with example data
anpi healthcheck              # exit 0 if the local server is healthy (used by Docker)
anpi reset-password <user>    # set a new password from stdin and sign out old sessions
anpi disable-sso              # turn off SSO configured in the panel
anpi export [file]            # write the configuration as JSON (stdout by default)
anpi import <file> [--replace]  # load a configuration export
anpi version                  # print the version
anpi update [--check]         # install the newest release (see Updating)
```

## Security notes

- **Everyone who can sign in is an admin.** Admins can make anpi send requests to any address, including the local network (monitors, *Run check now*, webhooks and SSO tests), and monitored services can redirect HTTP checks elsewhere. That is what a monitor needs to do, so only give accounts to people you trust with that.
- **SSO without a required role** lets every account the identity provider signs in become an admin. The settings page warns about this; set a role or group unless the realm is yours alone.
- **Sign-in is rate limited** per client address (10 failures per 15 minutes) and password hashing runs off the request threads with a small concurrency limit, so floods of sign-in attempts cannot stall the checks.
- **Alerts quote monitored responses** in some messages (for example a JSON value that did not match). Discord messages are escaped and send no mentions.
