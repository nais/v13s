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
        (workloads.state != 'processing' and ( workloads.image_name != @image_name or workloads.image_tag != @image_tag ))
    RETURNING
    id
;

-- name: SetWorkloadState :exec
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
        @state) ON CONFLICT
ON CONSTRAINT workload_id DO
UPDATE
    SET
        image_name = @image_name,
        image_tag = @image_tag,
        state = @state,
        updated_at = NOW()
;

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
