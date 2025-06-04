-- name: ListWorkloadStatus :many
SELECT w.name AS workload_name,
       w.workload_type,
       w.namespace,
       w.cluster,
       w.state AS workload_state,
       w.updated_at AS workload_updated_at,
       i.name AS image_name,
       i.tag AS image_tag,
       i.state AS image_state,
       i.updated_at AS image_updated_at
FROM workloads w
JOIN images i ON w.image_name = i.name AND w.image_tag = i.tag
WHERE
    (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
  AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
  AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
  AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
  ORDER BY w.id
;

-- name: ListRiverJobs :many
SELECT *
FROM river_job
WHERE
    (kind = 'add_workload' AND
    args->'Workload'->> 'Name' = sqlc.narg('workload_name')::TEXT AND
    args->'Workload'->> 'WorkloadType' = sqlc.narg('workload_type')::TEXT AND
    args->'Workload'->> 'Namespace' = sqlc.narg('namespace')::TEXT AND
    args->'Workload'->> 'Cluster' = sqlc.narg('cluster')::TEXT)
    OR
    (kind = 'get_attestation' AND
     args->> 'ImageName' = sqlc.narg('image_name')::TEXT AND
     args->> 'ImageTag' = sqlc.narg('image_tag')::TEXT)
    OR
    (kind = 'upload_attestation' AND
     args->> 'ImageName' = sqlc.narg('image_name')::TEXT AND
     args->> 'ImageTag' = sqlc.narg('image_tag')::TEXT)
    ORDER BY id
;

-- name: ListWorkloadStatusWithJobs :many
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
    rj.metadata::TEXT AS job_metadata,
    rj.errors::TEXT AS job_errors,
    rj.finalized_at AS job_finalized_at,
    rj.attempt AS job_attempt
FROM workloads w
         JOIN images i ON w.image_name = i.name AND w.image_tag = i.tag
         LEFT JOIN river_job rj ON (
    (rj.kind = 'add_workload' AND
     rj.args #>> '{Workload,Name}' = w.name AND
        rj.args #>> '{Workload,WorkloadType}' = w.workload_type AND
        rj.args #>> '{Workload,Namespace}' = w.namespace AND
        rj.args #>> '{Workload,Cluster}' = w.cluster
        )
        OR
    (rj.kind IN ('get_attestation', 'upload_attestation') AND
     rj.args #>> '{ImageName}' = w.image_name AND
        rj.args #>> '{ImageTag}' = w.image_tag
        )
    )
WHERE
    (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
  AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
  AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
  AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
ORDER BY w.id;