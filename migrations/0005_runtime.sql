-- Periods in which anpi was running and checking monitors; reports use them for monitoring coverage.
CREATE TABLE runtime (
    id INTEGER PRIMARY KEY,
    started_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX runtime_last_seen ON runtime (last_seen);
