-- name: ListRiverJobs :many
SELECT
    *
FROM
    river_job
WHERE (kind = 'add_workload'
    AND args -> 'Workload' ->> 'Name' = sqlc.narg('workload_name')::TEXT
    AND args -> 'Workload' ->> 'WorkloadType' = sqlc.narg('workload_type')::TEXT
    AND args -> 'Workload' ->> 'Namespace' = sqlc.narg('namespace')::TEXT
    AND args -> 'Workload' ->> 'Cluster' = sqlc.narg('cluster')::TEXT)
    OR (kind = 'get_attestation'
        AND args ->> 'ImageName' = sqlc.narg('image_name')::TEXT
        AND args ->> 'ImageTag' = sqlc.narg('image_tag')::TEXT)
    OR (kind = 'upload_attestation'
        AND args ->> 'ImageName' = sqlc.narg('image_name')::TEXT
        AND args ->> 'ImageTag' = sqlc.narg('image_tag')::TEXT)
ORDER BY
    id;

-- name: ListWorkloadStatusWithJobs :many
WITH filtered_workloads AS (
    SELECT
        *
    FROM
        workloads
    WHERE (sqlc.narg('cluster')::TEXT IS NULL
        OR CLUSTER = sqlc.narg('cluster')::TEXT)
    AND (sqlc.narg('namespace')::TEXT IS NULL
        OR namespace = sqlc.narg('namespace')::TEXT)
    AND (sqlc.narg('workload_types')::TEXT[] IS NULL
        OR workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
    AND (sqlc.narg('workload_name')::TEXT IS NULL
        OR name = sqlc.narg('workload_name')::TEXT)
),
total_count AS (
    SELECT
        COUNT(*) AS total
    FROM
        filtered_workloads
),
paged_workloads AS (
    SELECT
        *
    FROM
        filtered_workloads
    ORDER BY
        id
    LIMIT sqlc.arg('limit')
    OFFSET sqlc.arg('offset'))
SELECT
    w.name AS workload_name,
    w.workload_type,
    w.namespace,
    w.cluster,
    w.state AS workload_state,
    w.updated_at AS workload_updated_at,
    i.name AS image_name,
    i.tag AS image_tag,
    i.state AS image_state,
    i.updated_at AS image_updated_at,
    rj.id AS job_id,
    rj.kind AS job_kind,
    rj.state AS job_state,
    CASE WHEN rj.metadata::TEXT IS NOT NULL THEN
        rj.metadata::TEXT
    END AS job_metadata,
    CASE WHEN rj.errors::TEXT IS NOT NULL THEN
        rj.metadata::TEXT
    END AS job_errors,
    rj.finalized_at AS job_finalized_at,
    rj.attempt AS job_attempt,
    tc.total
FROM
    paged_workloads w
    JOIN total_count tc ON TRUE
    JOIN images i ON w.image_name = i.name
        AND w.image_tag = i.tag
    LEFT JOIN river_job rj ON ((rj.kind = 'add_workload'
                AND rj.args #>> '{Workload,Name}' = w.name
                AND rj.args #>> '{Workload,WorkloadType}' = w.workload_type
                AND rj.args #>> '{Workload,Namespace}' = w.namespace
                AND rj.args #>> '{Workload,Cluster}' = w.cluster)
            OR (rj.kind IN ('get_attestation', 'upload_attestation')
                AND rj.args #>> '{ImageName}' = w.image_name
                AND rj.args #>> '{ImageTag}' = w.image_tag))
    ORDER BY
        w.id;

-- name: ListWorkloadStatus :many
WITH filtered_workloads AS (
    SELECT
        *
    FROM
        workloads
    WHERE (
        CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN
            CLUSTER = sqlc.narg('cluster')::TEXT
        ELSE
            TRUE
        END)
    AND (
        CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN
            namespace = sqlc.narg('namespace')::TEXT
        ELSE
            TRUE
        END)
    AND (
        CASE WHEN sqlc.narg('workload_type')::TEXT IS NOT NULL THEN
            workload_type = sqlc.narg('workload_type')::TEXT
        ELSE
            TRUE
        END)
    AND (
        CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN
            name = sqlc.narg('workload_name')::TEXT
        ELSE
            TRUE
        END)
),
total_count AS (
    SELECT
        COUNT(*) AS total
    FROM
        filtered_workloads
),
paged_workloads AS (
    SELECT
        *
    FROM
        filtered_workloads
    ORDER BY
        id
    LIMIT sqlc.arg('limit')
    OFFSET sqlc.arg('offset'))
SELECT
    w.name AS workload_name,
    w.id,
    w.workload_type,
    w.namespace,
    w.cluster,
    w.state AS workload_state,
    w.updated_at AS workload_updated_at,
    i.name AS image_name,
    i.tag AS image_tag,
    i.state AS image_state,
    i.updated_at AS image_updated_at,
    tc.total
FROM
    paged_workloads w
    JOIN total_count tc ON TRUE
    JOIN images i ON w.image_name = i.name
        AND w.image_tag = i.tag
    ORDER BY
        w.id;

-- name: ListJobsForWorkload :many
WITH matched_workloads AS (
    SELECT
        w.id,
        w.name,
        w.workload_type,
        w.namespace,
        w.cluster,
        w.image_name,
        w.image_tag
    FROM
        workloads w
    WHERE (sqlc.narg('cluster')::TEXT IS NULL
        OR CLUSTER = sqlc.narg('cluster')::TEXT)
    AND (sqlc.narg('namespace')::TEXT IS NULL
        OR namespace = sqlc.narg('namespace')::TEXT)
    AND (sqlc.narg('workload_types')::TEXT[] IS NULL
        OR workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
    AND (sqlc.narg('workload_name')::TEXT IS NULL
        OR name = sqlc.narg('workload_name')::TEXT)
),
filtered_jobs AS (
    SELECT DISTINCT
        rj.id,
        rj.kind,
        rj.state,
        rj.metadata,
        rj.errors,
        rj.finalized_at,
        rj.attempt
    FROM
        river_job rj
        JOIN matched_workloads w ON ((rj.kind = 'add_workload'
                    AND rj.args #>> '{Workload,Name}' = w.name
                    AND rj.args #>> '{Workload,WorkloadType}' = w.workload_type
                    AND rj.args #>> '{Workload,Namespace}' = w.namespace
                    AND rj.args #>> '{Workload,Cluster}' = w.cluster)
                OR (rj.kind IN ('get_attestation', 'upload_attestation')
                    AND rj.args #>> '{ImageName}' = w.image_name
                    AND rj.args #>> '{ImageTag}' = w.image_tag))
),
total_count AS (
    SELECT
        COUNT(*) AS total
    FROM
        filtered_jobs
),
paged_jobs AS (
    SELECT
        *
    FROM
        filtered_jobs
    ORDER BY
        id DESC
    LIMIT sqlc.arg('limit')
    OFFSET sqlc.arg('offset'))
SELECT
    pj.id AS job_id,
    pj.kind AS job_kind,
    pj.state AS job_state,
    CASE WHEN pj.metadata::TEXT IS NOT NULL THEN
        pj.metadata::TEXT
    END AS job_metadata,
    CASE WHEN pj.errors::TEXT IS NOT NULL THEN
        pj.errors::TEXT
    END AS job_errors,
    pj.finalized_at AS job_finalized_at,
    pj.attempt AS job_attempt,
    tc.total
FROM
    paged_jobs pj
JOIN total_count tc ON TRUE
ORDER BY
    pj.id DESC;
