-- +goose Up
CREATE TABLE IF NOT EXISTS kev_sync_state (
    id          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1), -- singleton row
    etag        TEXT NOT NULL DEFAULT '',
    synced_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down
DROP TABLE IF EXISTS kev_sync_state;
