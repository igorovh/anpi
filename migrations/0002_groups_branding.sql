CREATE TABLE monitor_groups (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

ALTER TABLE monitors ADD COLUMN group_id INTEGER REFERENCES monitor_groups (id) ON DELETE SET NULL;
ALTER TABLE monitors ADD COLUMN public_name TEXT NOT NULL DEFAULT '';

CREATE TABLE assets (
    key          TEXT PRIMARY KEY,
    content_type TEXT    NOT NULL,
    data         BLOB    NOT NULL,
    updated_at   INTEGER NOT NULL
);
