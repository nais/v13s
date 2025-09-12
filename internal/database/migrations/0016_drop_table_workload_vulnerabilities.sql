-- +goose Up
DROP TABLE workload_vulnerabilities;

-- +goose Down
CREATE TABLE workload_vulnerabilities
(
    id                 UUID PRIMARY KEY                  DEFAULT gen_random_uuid(),
    workload_id        UUID                     NOT NULL REFERENCES workloads (id) ON DELETE CASCADE,
    vulnerability_id   UUID                     NOT NULL REFERENCES vulnerabilities (id) ON DELETE CASCADE,
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    became_critical_at TIMESTAMP WITH TIME ZONE,
    resolved_at        TIMESTAMP WITH TIME ZONE,
    UNIQUE (workload_id, vulnerability_id)
);

CREATE INDEX idx_workload_vulnerabilities_workload_id
    ON workload_vulnerabilities (workload_id);

CREATE INDEX idx_workload_vulnerabilities_vulnerability_id
    ON workload_vulnerabilities (vulnerability_id);
