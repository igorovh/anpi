# REST API and Terraform

[← Back to the README](../README.md)

anpi has a JSON API under `/api/v1` for monitors, groups, notification channels and maintenance windows. The [Terraform provider](#terraform) uses it, and scripts can too. The public, read-only [`/api/status.json`](monitoring.md#status-page-and-api) needs no token.

## Tokens

Create a token under **Settings → API tokens**, or on the server:

```sh
anpi api-token terraform    # prints the token once
```

Tokens belong to the instance, not to a user, and work until they are revoked under **Settings → API tokens**. A token can change all of the objects below but cannot open the panel, manage users or change settings. Send it as a bearer token:

```sh
curl -H "Authorization: Bearer anpi_…" https://status.example.com/api/v1/monitors
```

## Terraform

The provider lives in its own repository: [igorovh/terraform-provider-anpi](https://github.com/igorovh/terraform-provider-anpi).

```hcl
terraform {
  required_providers {
    anpi = {
      source  = "igorovh/anpi"
      version = "~> 0.1"
    }
  }
}

provider "anpi" {
  url = "https://status.example.com" # or ANPI_URL
  # token from ANPI_TOKEN
}

resource "anpi_group" "product" {
  name = "Product"
}

resource "anpi_monitor" "api" {
  name     = "API"
  kind     = "http"
  target   = "https://api.example.com/health"
  public   = true
  group_id = anpi_group.product.id
}
```

It manages `anpi_monitor`, `anpi_group`, `anpi_notification_channel` and `anpi_maintenance`; existing objects can be imported by the ID in the panel URL. Changes made in the panel show up as drift in the next plan. See the provider's README for every argument.

## Conventions

- Requests and responses are JSON. Errors look like `{"error": "URL must start with http:// or https://"}` with status `400` (invalid input), `401` (missing or wrong token) or `404`.
- `POST` creates and answers `201` with the new object. `PUT` replaces the whole object: fields left out get their defaults, as in the panel form. `DELETE` answers `204`.
- Unknown fields are rejected, so typos do not pass silently. `id` and `push_token` from a response are accepted and ignored, so a fetched object can be edited and sent back.
- IDs are the numbers in panel URLs.

| Method | Path | |
| --- | --- | --- |
| `GET` | `/api/v1/info` | anpi version and the name of the token |
| `GET`, `POST` | `/api/v1/monitors` | list, create |
| `GET`, `PUT`, `DELETE` | `/api/v1/monitors/{id}` | read, replace, delete |
| `GET`, `POST` | `/api/v1/groups` | |
| `GET`, `PUT`, `DELETE` | `/api/v1/groups/{id}` | |
| `GET`, `POST` | `/api/v1/notification-channels` | |
| `GET`, `PUT`, `DELETE` | `/api/v1/notification-channels/{id}` | |
| `GET`, `POST` | `/api/v1/maintenances` | |
| `GET`, `PUT`, `DELETE` | `/api/v1/maintenances/{id}` | |

## Monitors

```json
{
  "name": "API",
  "kind": "http",
  "target": "https://api.example.com/health",
  "interval_s": 30,
  "headers": "Authorization: Bearer secret",
  "content_kind": "json_path",
  "content_value": "$.status",
  "content_expected": "ok",
  "public": true,
  "group_id": 3,
  "parent_id": null,
  "channel_ids": [1]
}
```

| Field | Default | Notes |
| --- | --- | --- |
| `name` | required | up to 100 characters |
| `kind` | required | `http`, `websocket`, `tcp`, `ping`, `dns`, `push`, `aggregate` |
| `target` | `""` | URL for `http`/`websocket`, host for `tcp`/`ping`, domain for `dns`; ignored by `push` and `aggregate` |
| `port` | `null` | required for `tcp`, ignored otherwise |
| `method` | `GET` | `http` only |
| `headers` | `""` | one `Name: value` per line |
| `body` | `""` | |
| `interval_s` | `60` | 5 to 604800 |
| `retry_interval_s` | `60` | 5 to 604800 |
| `timeout_s` | `30` | 1 to 300 |
| `failure_threshold` | `3` | 1 to 100 |
| `expected_status` | `200-299` | |
| `ip_family` | `auto` | `auto`, `v4`, `v6` |
| `follow_redirects` | `true` | |
| `ignore_tls` | `false` | |
| `content_kind` | `none` | `none`, `contains`, `not_contains`, `regex`, `json_path`; `http`/`websocket` only |
| `content_value` | `""` | |
| `content_expected` | `""` | value for `json_path`, or the expected answer of a `dns` monitor |
| `ssl_warn_days` | `14` | 0 to 365 |
| `dns_record_type` | `A` | `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `CAA` |
| `dns_server` | `""` | system resolver when empty |
| `active` | `true` | `false` pauses checks |
| `public` | `false` | show on the status page |
| `public_name` | `""` | |
| `group_id` | `null` | |
| `parent_id` | `null` | one level of nesting only |
| `channel_ids` | see notes | left out: a new monitor gets the channels marked as default, an update keeps the current ones |

Some settings a kind does not use are reset: `port` outside `tcp` comes back as `null`, `method` outside `http` as `GET`, `target` of `push` and `aggregate` as `""`, and response rules outside `http`/`websocket` as `none`. Responses add `id` and, for `push` monitors, `push_token`; the push URL is `/api/push/<push_token>`. The token stays the same across updates.

## Groups

`{"name": "Product", "sort_order": 10}`. `name` is required (up to 60 characters). Without `sort_order`, a new group goes last and an update keeps the current order. Deleting a group leaves its monitors ungrouped.

## Notification channels

```json
{ "name": "Discord #alerts", "kind": "discord", "active": true, "is_default": false, "config": { "webhook_url": "https://discord.com/api/webhooks/…" } }
```

`kind` is `discord`, `telegram`, `ntfy`, `email` or `webhook`. `active` defaults to `true`, `is_default` to `false`. `config` has the same fields as the panel form: `webhook_url`, `username`, `bot_token`, `chat_id`, `api_base`, `server`, `topic`, `token`, `priority`, `smtp_host`, `smtp_port`, `smtp_security`, `smtp_username`, `smtp_password`, `email_from`, `email_to`, `url`. Responses include secrets, because the token already allows changing them.

## Maintenance windows

```json
{ "title": "Database upgrade", "starts_at": "2030-05-02T00:00:00+02:00", "ends_at": "2030-05-02T01:00:00+02:00", "all_monitors": false, "monitor_ids": [2, 5] }
```

Times are RFC 3339 and come back in UTC (`2030-05-01T22:00:00Z`). `ends_at` must be after `starts_at`, and either `all_monitors` is `true` or `monitor_ids` lists at least one monitor.
