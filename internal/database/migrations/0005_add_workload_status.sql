-- +goose Up

CREATE TYPE workload_state AS ENUM ('initialized','updated', 'no_attestation');

ALTER TABLE workloads
    ADD COLUMN state workload_state NOT NULL DEFAULT 'initialized';
