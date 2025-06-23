-- +goose Up

CREATE TABLE source_keys
(
    name       TEXT NOT NULL,
    uuid       TEXT PRIMARY KEY,
    key        TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);