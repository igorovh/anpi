ALTER TABLE monitors ADD COLUMN parent_id INTEGER REFERENCES monitors (id) ON DELETE SET NULL;
CREATE INDEX monitors_parent ON monitors (parent_id);
