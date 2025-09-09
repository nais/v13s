-- +goose Up

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS severity_since TIMESTAMP WITH TIME ZONE DEFAULT NULL;

UPDATE vulnerabilities
SET severity_since = became_critical_at
WHERE became_critical_at IS NOT NULL;

ALTER TABLE vulnerabilities
DROP
COLUMN became_critical_at;