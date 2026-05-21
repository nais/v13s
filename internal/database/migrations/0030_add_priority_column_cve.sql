-- +goose Up
ALTER TABLE cve
    ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 4;

ALTER TABLE vulnerability_summary
    ADD COLUMN IF NOT EXISTS act_now INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS high_priority INT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE vulnerability_summary
    DROP COLUMN IF EXISTS act_now,
    DROP COLUMN IF EXISTS high_priority;

ALTER TABLE cve
    DROP COLUMN IF EXISTS priority;
