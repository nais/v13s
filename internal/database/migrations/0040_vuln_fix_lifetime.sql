-- +goose Up
CREATE TABLE vuln_fix_lifetime(
    workload_id UUID NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    severity INT NOT NULL,
    introduced_at DATE NOT NULL,
    fixed_at DATE,
    PRIMARY KEY (workload_id, severity, introduced_at)
);

CREATE INDEX idx_vuln_fix_lifetime_fixed_at ON vuln_fix_lifetime(fixed_at)
WHERE
    fixed_at IS NOT NULL;

INSERT INTO vuln_fix_lifetime(
    workload_id,
    severity,
    introduced_at,
    fixed_at)
SELECT
    v.workload_id,
    v.severity,
    v.introduced_at,
    CASE WHEN v.is_fixed THEN
        v.fixed_at
    END
FROM
    vuln_upsert_data_for_date(CURRENT_DATE) v
WHERE
    v.workload_id IN (
        SELECT
            id
        FROM
            workloads);

DROP TABLE vuln_fix_summary;

-- +goose Down
CREATE TABLE vuln_fix_summary(
    workload_id UUID REFERENCES workloads(id) ON DELETE CASCADE,
    severity INT NOT NULL,
    introduced_at DATE NOT NULL,
    fixed_at DATE,
    fix_duration INT,
    is_fixed BOOLEAN NOT NULL,
    snapshot_date DATE NOT NULL,
    PRIMARY KEY (workload_id, severity, introduced_at, snapshot_date)
);

CREATE INDEX idx_vuln_fix_summary_workload ON vuln_fix_summary(workload_id, severity, introduced_at);

CREATE INDEX idx_vuln_fix_summary_snapshot_fixed ON vuln_fix_summary(snapshot_date, is_fixed);

CREATE INDEX idx_vuln_fix_summary_fixed_at ON vuln_fix_summary(fixed_at)
WHERE
    is_fixed = TRUE;

CREATE INDEX idx_vuln_fix_summary_is_fixed ON vuln_fix_summary(is_fixed);

CREATE INDEX idx_vuln_fix_summary_snapshot_severity ON vuln_fix_summary(snapshot_date, severity);

SELECT
    backfill_vuln_fix_summary();

DROP TABLE vuln_fix_lifetime;
