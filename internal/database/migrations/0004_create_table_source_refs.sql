-- +goose Up

CREATE TABLE source_refs
(
    id          UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    workload_id UUID NOT NULL,
    source_id   UUID NOT NULL,
    source_type TEXT NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()             NOT NULL
)
;