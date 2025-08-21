-- +goose Up

ALTER TABLE vulnerabilities
    ADD COLUMN last_severity INT,
    ADD COLUMN became_critical_at TIMESTAMP WITH TIME ZONE
;