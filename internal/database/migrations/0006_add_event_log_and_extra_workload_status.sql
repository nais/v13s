-- +goose Up

CREATE TABLE workload_event_log
(
    id            UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    name          TEXT                                               NOT NULL,
    workload_type TEXT                                               NOT NULL,
    namespace     TEXT                                               NOT NULL,
    cluster       TEXT                                               NOT NULL,
    event_type    TEXT                                               NOT NULL,
    event_data    TEXT                                               NOT NULL,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()             NOT NULL
);

ALTER TYPE workload_state ADD VALUE 'processing';
ALTER TYPE workload_state ADD VALUE 'failed';
ALTER TYPE workload_state ADD VALUE 'unrecoverable';
ALTER TYPE workload_state ADD VALUE 'resync';
