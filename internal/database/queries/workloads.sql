-- name: UpsertWorkload :one
INSERT INTO workloads(
    name,
    workload_type,
    namespace,
    cluster,
    image_name,
    image_tag,
    state)
VALUES (
    @name,
    @workload_type,
    @namespace,
    @cluster,
    @image_name,
    @image_tag,
    'initialized')
ON CONFLICT ON CONSTRAINT workload_id
    DO UPDATE SET
        image_name = @image_name,
        image_tag = @image_tag,
        state = 'initialized',
        updated_at = NOW()
    RETURNING
        id;

-- name: InitializeWorkload :one
WITH upserted AS (
    INSERT INTO workloads(
        name,
        workload_type,
        namespace,
        cluster,
        image_name,
        image_tag,
        state)
    VALUES (
        @name,
        @workload_type,
        @namespace,
        @cluster,
        @image_name,
        @image_tag,
        'processing')
ON CONFLICT ON CONSTRAINT workload_id
    DO UPDATE SET
        state = 'processing',
        updated_at = NOW(),
        image_name = @image_name,
        image_tag = @image_tag
    WHERE
        workloads.state = 'resync'
        OR (
            workloads.image_name != @image_name
            OR workloads.image_tag != @image_tag)
    RETURNING
        id)
    SELECT
        id
    FROM
        upserted
    UNION ALL
    SELECT
        NULL::UUID
    WHERE
        NOT EXISTS (
            SELECT
                1
            FROM
                upserted)
    LIMIT 1;

-- name: SetWorkloadState :many
WITH updated AS (
    UPDATE
        workloads
    SET
        state = @state,
        updated_at = NOW()
    WHERE ((sqlc.narg('cluster')::TEXT IS NULL
            OR CLUSTER = sqlc.narg('cluster')::TEXT)
        AND (sqlc.narg('namespace')::TEXT IS NULL
            OR namespace = sqlc.narg('namespace')::TEXT)
        AND (sqlc.narg('workload_type')::TEXT IS NULL
            OR workload_type = sqlc.narg('workload_type')::TEXT)
        AND (sqlc.narg('workload_name')::TEXT IS NULL
            OR name = sqlc.narg('workload_name')::TEXT))
    AND state = @old_state
RETURNING
    *
)
SELECT
    *
FROM
    updated
ORDER BY
    CLUSTER,
    namespace,
    name,
    updated_at DESC;

-- name: UpdateWorkloadState :exec
UPDATE
    workloads
SET
    state = @state
WHERE
    id = @id;

-- name: CreateWorkload :one
INSERT INTO workloads(
    name,
    workload_type,
    namespace,
    cluster,
    image_name,
    image_tag)
VALUES (
    @name,
    @workload_type,
    @namespace,
    @cluster,
    @image_name,
    @image_tag)
RETURNING
    *;

-- name: GetWorkload :one
SELECT
    *
FROM
    workloads
WHERE
    name = @name
    AND workload_type = @workload_type
    AND namespace = @namespace
    AND CLUSTER = @cluster;

-- name: DeleteWorkload :one
DELETE FROM workloads
WHERE name = @name
    AND workload_type = @workload_type
    AND namespace = @namespace
    AND CLUSTER = @cluster
RETURNING
    id;

-- name: AddWorkloadEvent :exec
INSERT INTO workload_event_log(
    name,
    workload_type,
    namespace,
    cluster,
    event_type,
    event_data,
    subsystem)
VALUES (
    @name,
    @workload_type,
    @namespace,
    @cluster,
    @event_type,
    @event_data,
    @subsystem)
ON CONFLICT
    DO NOTHING;

-- name: ListWorkloadsByImage :many
SELECT
    w.id,
    w.name,
    w.workload_type,
    w.namespace,
    w.cluster,
    w.image_name,
    w.image_tag,
    w.state,
    w.created_at,
    w.updated_at,
    i.state AS image_state,
    i.sbom_processing_started_at
FROM
    workloads w
    LEFT JOIN images i ON i.name = w.image_name
        AND i.tag = w.image_tag
WHERE
    w.image_name = @image_name
    AND w.image_tag = @image_tag
ORDER BY
    w.name DESC,
    w.cluster DESC,
    w.updated_at DESC;

-- name: UpdateWorkloadStateByImage :exec
UPDATE
    workloads
SET
    state = @state,
    updated_at = NOW()
WHERE
    image_name = @image_name
    AND image_tag = @image_tag
    AND state NOT IN ('failed', 'unrecoverable');

-- name: ListWorkloadsByCluster :many
SELECT
    *
FROM
    workloads
WHERE
    CLUSTER = @cluster
ORDER BY
    (name,
        namespace,
        CLUSTER,
        updated_at) DESC;

-- name: BatchUpdateWorkloadStateByImage :batchexec
UPDATE
    workloads
SET
    state = @state,
    updated_at = NOW()
WHERE
    image_name = @image_name
    AND image_tag = @image_tag
    AND state NOT IN ('failed', 'unrecoverable');
