-- +goose Up
ALTER TABLE workloads
    ADD COLUMN labels JSONB NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE workloads
    DROP COLUMN labels;
