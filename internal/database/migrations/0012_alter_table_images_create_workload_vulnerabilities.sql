-- +goose Up

ALTER TABLE vulnerabilities
    ADD COLUMN became_critical_at timestamptz NULL DEFAULT NULL;

ALTER TABLE vulnerabilities
    ADD COLUMN last_severity INT NOT NULL DEFAULT 5; -- Default severity (unknown)

ALTER TABLE images
    ADD COLUMN ready_for_resync_at timestamptz;