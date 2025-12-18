-- +goose Up
ALTER TABLE vulnerabilities
    ADD COLUMN cvss_score FLOAT8 NULL DEFAULT NULL;
