-- +goose Up
ALTER TABLE workload_event_log
    ADD COLUMN subsystem TEXT NOT NULL DEFAULT 'unknown';
