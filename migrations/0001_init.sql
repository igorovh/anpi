CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT,
    oidc_issuer   TEXT,
    oidc_subject  TEXT,
    created_at    INTEGER NOT NULL,
    UNIQUE (oidc_issuer, oidc_subject)
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf       TEXT    NOT NULL,
    id_token   TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE monitors (
    id                  INTEGER PRIMARY KEY,
    name                TEXT    NOT NULL,
    kind                TEXT    NOT NULL,
    target              TEXT    NOT NULL DEFAULT '',
    port                INTEGER,
    method              TEXT    NOT NULL DEFAULT 'GET',
    headers             TEXT    NOT NULL DEFAULT '',
    body                TEXT    NOT NULL DEFAULT '',
    interval_s          INTEGER NOT NULL DEFAULT 60,
    retry_interval_s    INTEGER NOT NULL DEFAULT 30,
    timeout_s           INTEGER NOT NULL DEFAULT 30,
    failure_threshold   INTEGER NOT NULL DEFAULT 3,
    expected_status     TEXT    NOT NULL DEFAULT '200-299',
    ip_family           TEXT    NOT NULL DEFAULT 'auto',
    follow_redirects    INTEGER NOT NULL DEFAULT 1,
    ignore_tls          INTEGER NOT NULL DEFAULT 0,
    content_kind        TEXT    NOT NULL DEFAULT 'none',
    content_value       TEXT    NOT NULL DEFAULT '',
    content_expected    TEXT    NOT NULL DEFAULT '',
    ssl_warn_days       INTEGER NOT NULL DEFAULT 14,
    dns_record_type     TEXT    NOT NULL DEFAULT 'A',
    dns_server          TEXT    NOT NULL DEFAULT '',
    push_token          TEXT UNIQUE,
    active              INTEGER NOT NULL DEFAULT 1,
    public              INTEGER NOT NULL DEFAULT 0,
    ssl_notified_days   INTEGER,
    ssl_notified_expiry INTEGER,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

-- status: 0 down, 1 up, 2 pending, 3 maintenance
CREATE TABLE heartbeats (
    id              INTEGER PRIMARY KEY,
    monitor_id      INTEGER NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    ts              INTEGER NOT NULL,
    status          INTEGER NOT NULL,
    status_code     INTEGER,
    dns_ms          REAL,
    connect_ms      REAL,
    tls_ms          REAL,
    ttfb_ms         REAL,
    total_ms        REAL,
    remote_ip       TEXT,
    message         TEXT    NOT NULL DEFAULT '',
    cert_expires_at INTEGER
);
CREATE INDEX heartbeats_monitor_ts ON heartbeats (monitor_id, ts);
CREATE INDEX heartbeats_ts ON heartbeats (ts);

CREATE TABLE heartbeats_hourly (
    monitor_id     INTEGER NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    hour           INTEGER NOT NULL,
    up             INTEGER NOT NULL,
    down           INTEGER NOT NULL,
    total          INTEGER NOT NULL,
    avg_total_ms   REAL,
    min_total_ms   REAL,
    max_total_ms   REAL,
    avg_dns_ms     REAL,
    avg_connect_ms REAL,
    avg_tls_ms     REAL,
    avg_ttfb_ms    REAL,
    PRIMARY KEY (monitor_id, hour)
) WITHOUT ROWID;
CREATE INDEX heartbeats_hourly_hour ON heartbeats_hourly (hour);

CREATE TABLE incidents (
    id         INTEGER PRIMARY KEY,
    monitor_id INTEGER NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER,
    message    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX incidents_monitor ON incidents (monitor_id, started_at);

CREATE TABLE notification_channels (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    kind       TEXT    NOT NULL,
    config     TEXT    NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE monitor_notifications (
    monitor_id INTEGER NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    channel_id INTEGER NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    PRIMARY KEY (monitor_id, channel_id)
);

CREATE TABLE maintenances (
    id           INTEGER PRIMARY KEY,
    title        TEXT    NOT NULL,
    starts_at    INTEGER NOT NULL,
    ends_at      INTEGER NOT NULL,
    all_monitors INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL
);

CREATE TABLE maintenance_monitors (
    maintenance_id INTEGER NOT NULL REFERENCES maintenances (id) ON DELETE CASCADE,
    monitor_id     INTEGER NOT NULL REFERENCES monitors (id) ON DELETE CASCADE,
    PRIMARY KEY (maintenance_id, monitor_id)
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
