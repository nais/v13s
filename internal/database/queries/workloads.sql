-- name: UpsertWorkload :exec
INSERT INTO workloads(
    name,
    workload_type,
    namespace,
    cluster,
    image_name,
    image_tag
)
VALUES (
    @name,
    @workload_type,
    @namespace,
    @cluster,
    @image_name,
    @image_tag
) ON CONFLICT
    ON CONSTRAINT workload_id DO
        UPDATE
    SET
        image_name = @image_name,
        image_tag = @image_tag,
        updated_at = NOW()
;

-- name: CreateWorkload :one
INSERT INTO
    workloads (name, workload_type, namespace, cluster, image_name, image_tag)
VALUES
    (@name, @workload_type, @namespace, @cluster, @image_name, @image_tag)
RETURNING
    *
;

-- name: UpdateWorkload :one
UPDATE workloads
SET
    image_name = @image_name,
    image_tag = @image_tag,
    updated_at = NOW()
WHERE
    cluster = @cluster AND
    namespace = @namespace AND
    workload_type = @workload_type AND
    name = @name
RETURNING
    *
;

-- name: ListWorkloadsByImage :many
SELECT *
FROM workloads
WHERE image_name = @image_name
  AND image_tag = @image_tag
ORDER BY
    (name, cluster, updated_at) DESC;
