# Monitoring

[← Back to the README](../README.md)

## Highlights

- **Light.** The release binary is about 9 MB and uses roughly 20 MB of RAM with a handful of monitors (2–5 MB inside Docker). There is no Node, no external database and no CDN; fonts and assets are built in.
- **Tells you *why* something failed.** HTTP checks record DNS, connect, TLS, server-wait and transfer times separately. Auto IP mode shows when IPv6 failed and IPv4 had to take over.
- **Quiet.** A monitor is only marked down after N failures in a row, and each outage sends one alert when it starts and one when it ends.
- **Readable.** Every monitor page spells out exactly what is requested and what counts as up, e.g. *GET https://api.example.com/health — JSON $.status equals "ok" — every 60s, every 30s while failing*.

## Monitors

| Type | What is checked |
|---|---|
| **HTTP(S)** | Method, headers, body; accepted status codes such as `200-299, 301, 4xx`; optional response rule; redirects; certificate expiry |
| **WebSocket** | `ws://` / `wss://` handshake, optional message to send and a rule for the first reply |
| **TCP port** | The port accepts a connection |
| **Ping** | ICMP echo reply |
| **DNS** | A, AAAA, CNAME, MX, NS, TXT, SOA or CAA record, optional resolver and expected value |
| **Push** | Your cron job calls a URL; no call within the interval counts as a failure |
| **Aggregate** | No checks of its own; shows the worst status of the monitors placed under it |

Each monitor has its own interval (default 60 s), retry interval while failing (30 s), timeout, number of failures before it is marked down (3) and IP version (auto, IPv4 only, IPv6 only).

**Response rules.** A response or WebSocket reply can be required to *contain* or *not contain* text, *match a regular expression*, or *have a JSON field*, optionally with a value (`$.status` equals `ok`). The form shows a summary such as *"Up when the status is 200-299 and JSON $.status equals “ok”"*. **Run check now** tries the settings before you save them and shows the status, timings and the start of the response.

**Groups and sub-monitors.** Drag monitors onto a group header to move them, or onto another monitor to put them underneath, e.g. endpoints under an "API" aggregate. Parents show the worst status of their children, and the status page can collapse them.

**Certificates.** HTTPS and WSS monitors warn at the configured window (default 14 days), then at 7, 3 and 1 days before expiry. Each step alerts once, and a renewed certificate starts the sequence again.

## Alerts

Discord, Telegram, ntfy, e-mail (SMTP) and a generic JSON webhook. Add channels under **Notifications**, use **Send test**, then tick them in a monitor's settings. Alerts are sent when a monitor goes down, when it comes back (with the downtime) and when a certificate is about to expire. **Maintenance windows** turn alerts off for chosen monitors; checks keep running and are shown as maintenance.

## Status page and API

`/` lists public monitors by group, with 30-day uptime bars, live updates and recent incidents. Each monitor can have a public name, so internal names stay private. Set the site name and logo under **Settings → Branding**; the logo is also used as the favicon.

`GET /api/status.json` returns the same data for other tools:

```json
{
  "title": "Example status",
  "status": "partial_outage",
  "monitors": [
    { "id": 2, "name": "API", "group": "Product", "status": "up", "uptime_24h": "99.94%", "uptime_30d": "99.88%" },
    { "id": 3, "parent": 2, "name": "Search", "group": "Product", "status": "up", "uptime_24h": "100%", "uptime_30d": "99.94%" }
  ]
}
```

Push monitors show their URL on the monitor page:

```sh
curl -fsS "https://status.example.com/api/push/<token>?status=up&msg=OK&ping=1234"
```
