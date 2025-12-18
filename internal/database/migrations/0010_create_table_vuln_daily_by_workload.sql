-- +goose Up
CREATE TABLE vuln_daily_by_workload(
    snapshot_date DATE NOT NULL,
    workload_id UUID NOT NULL,
    workload_name TEXT,
    cluster text,
    namespace TEXT,
    workload_type TEXT,
    critical INT,
    high INT,
    medium INT,
    low INT,
    unassigned INT,
    total INT,
    risk_score INT,
    PRIMARY KEY (snapshot_date, workload_id),
    CONSTRAINT workload_type_namespace_cluster UNIQUE (snapshot_date, workload_name, workload_type, namespace, CLUSTER)
);
