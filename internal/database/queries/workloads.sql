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

-- name: DeleteWorkload :exec
DELETE FROM workloads
WHERE name = @name
  AND workload_type = @workload_type
  AND namespace = @namespace
  AND cluster = @cluster
;

-- name: ListWorkloadsByImage :many
SELECT *
FROM workloads
WHERE image_name = @image_name
  AND image_tag = @image_tag
ORDER BY
    (name, cluster, updated_at) DESC;
