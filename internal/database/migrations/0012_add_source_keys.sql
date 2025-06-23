-- +goose Up

CREATE TABLE source_keys
(
    uuid       TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    team_name  TEXT NOT NULL,
    key        TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);