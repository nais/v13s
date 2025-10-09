-- +goose Up

-- vuln_fix_summary indexes
CREATE INDEX IF NOT EXISTS idx_vuln_fix_summary_workload
    ON vuln_fix_summary(workload_id, severity, introduced_at);

CREATE INDEX IF NOT EXISTS idx_vuln_fix_summary_snapshot_fixed
    ON vuln_fix_summary(snapshot_date, is_fixed);

CREATE INDEX IF NOT EXISTS idx_vuln_fix_summary_fixed_at
    ON vuln_fix_summary(fixed_at)
    WHERE is_fixed = true;

CREATE INDEX IF NOT EXISTS idx_vuln_fix_summary_is_fixed
    ON vuln_fix_summary(is_fixed);

CREATE INDEX IF NOT EXISTS idx_vuln_fix_summary_snapshot_severity
    ON vuln_fix_summary(snapshot_date, severity);

-- workloads indexes
CREATE INDEX IF NOT EXISTS idx_workloads_image_tag
    ON workloads(image_name, image_tag);

CREATE INDEX IF NOT EXISTS idx_workloads_cluster_namespace_name
    ON workloads(cluster, namespace, name);

CREATE INDEX IF NOT EXISTS idx_workloads_type
    ON workloads(workload_type);

-- vulnerability_summary indexes
CREATE INDEX IF NOT EXISTS idx_vuln_summary_updated_at
    ON vulnerability_summary(updated_at DESC);