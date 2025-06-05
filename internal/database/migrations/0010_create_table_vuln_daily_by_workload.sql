-- +goose Up
CREATE TABLE vuln_daily_by_workload (
    snapshot_date  date NOT NULL,
    workload_id    uuid NOT NULL,
    workload_name  text,
    cluster        text,
    namespace      text,
    workload_type  text,
    critical       int,
    high           int,
    medium         int,
    low            int,
    unassigned     int,
    total          int,
    risk_score     int,
    PRIMARY KEY (snapshot_date, workload_id),
    CONSTRAINT workload_type_namespace_cluster UNIQUE (snapshot_date,workload_name, workload_type, namespace, cluster)
);
