-- name: UpsertWorkload :one
INSERT INTO workloads(name,
                      workload_type,
                      namespace,
                      cluster,
                      image_name,
                      image_tag,
                      state)
VALUES (@name,
        @workload_type,
        @namespace,
        @cluster,
        @image_name,
        @image_tag,
        'initialized') ON CONFLICT
ON CONSTRAINT workload_id DO
UPDATE
    SET
        image_name = @image_name,
    image_tag = @image_tag,
    state = 'initialized',
    updated_at = NOW()
    RETURNING
    id
;

-- name: InitializeWorkload :one
INSERT INTO workloads(name,
                      workload_type,
                      namespace,
                      cluster,
                      image_name,
                      image_tag,
                      state)
VALUES (@name,
        @workload_type,
        @namespace,
        @cluster,
        @image_name,
        @image_tag,
        'processing') ON CONFLICT
ON CONSTRAINT workload_id DO
UPDATE
    SET
        state = 'processing',
        updated_at = NOW(),
        image_name = @image_name,
        image_tag = @image_tag
    WHERE workloads.state = 'failed' or
        workloads.state = 'resync' or
        (workloads.image_name != @image_name or workloads.image_tag != @image_tag)
    RETURNING
    id
;

-- name: SetWorkloadState :many
WITH updated AS (
UPDATE workloads
SET state      = @state,
    updated_at = NOW()
WHERE (sqlc.narg('cluster')::TEXT IS NULL OR cluster = sqlc.narg('cluster')::TEXT)
  AND (sqlc.narg('namespace')::TEXT IS NULL OR namespace = sqlc.narg('namespace')::TEXT)
  AND (sqlc.narg('workload_type')::TEXT IS NULL OR workload_type = sqlc.narg('workload_type')::TEXT)
  AND (sqlc.narg('workload_name')::TEXT IS NULL OR name = sqlc.narg('workload_name')::TEXT)
  AND state = @old_state
    RETURNING *
)
SELECT *
FROM updated
ORDER BY cluster, namespace, name, updated_at DESC;

-- name: UpdateWorkloadState :exec
UPDATE workloads
SET state = @state
WHERE id = @id;

-- name: CreateWorkload :one
INSERT INTO workloads (name, workload_type, namespace, cluster, image_name, image_tag)
VALUES (@name, @workload_type, @namespace, @cluster, @image_name, @image_tag) RETURNING
    *
;

-- name: GetWorkload :one
SELECT *
FROM workloads
WHERE name = @name
  AND workload_type = @workload_type
  AND namespace = @namespace
  AND cluster = @cluster
;

-- name: DeleteWorkload :one
DELETE
FROM workloads
WHERE name = @name
  AND workload_type = @workload_type
  AND namespace = @namespace
  AND cluster = @cluster RETURNING
    id
;

-- name: AddWorkloadEvent :exec
INSERT INTO workload_event_log (name,
                             workload_type,
                             namespace,
                             cluster,
                             event_type,
                             event_data,
                              subsystem)
VALUES (@name,
        @workload_type,
        @namespace,
        @cluster,
        @event_type,
        @event_data,
        @subsystem) ON
        CONFLICT DO NOTHING;


-- name: ListWorkloadsByImage :many
SELECT *
FROM workloads
WHERE image_name = @image_name
  AND image_tag = @image_tag
ORDER BY (name, cluster, updated_at) DESC;

-- name: ListWorkloadsByCluster :many
SELECT *
FROM workloads
WHERE cluster = @cluster
ORDER BY (name, namespace, cluster, updated_at) DESC;
