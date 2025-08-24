-- +goose Up

ALTER TABLE vulnerabilities
    ADD COLUMN last_severity INT,
    ADD COLUMN became_critical_at TIMESTAMP WITH TIME ZONE
;

ALTER TABLE images
    ADD COLUMN ready_for_resync_at timestamptz;