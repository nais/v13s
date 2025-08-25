-- +goose Up


CREATE TABLE workload_vulnerabilities
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workload_id UUID NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    package TEXT NOT NULL,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    became_critical_at TIMESTAMPTZ,
    last_severity INT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workload_id, package, cve_id)
);

ALTER TABLE vulnerabilities
    ADD COLUMN last_severity INT,
    ADD COLUMN became_critical_at TIMESTAMP WITH TIME ZONE
;

ALTER TABLE images
    ADD COLUMN ready_for_resync_at timestamptz;