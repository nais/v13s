-- +goose Up
ALTER TABLE cve
    ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 4;

ALTER TABLE vulnerability_summary
    ADD COLUMN IF NOT EXISTS priority_act_now INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS priority_high INT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE vulnerability_summary
    DROP COLUMN IF EXISTS priority_act_now,
    DROP COLUMN IF EXISTS priority_high;

ALTER TABLE cve
    DROP COLUMN IF EXISTS priority;
