ALTER TABLE monitors ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;
UPDATE monitors SET sort_order = r.n
FROM (SELECT id, ROW_NUMBER() OVER (ORDER BY name COLLATE NOCASE, id) AS n FROM monitors) AS r
WHERE r.id = monitors.id;
