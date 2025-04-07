-- name: UpsertWorkload :one
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
RETURNING
    id
;

-- name: CreateWorkload :one
INSERT INTO
    workloads (name, workload_type, namespace, cluster, image_name, image_tag)
VALUES
    (@name, @workload_type, @namespace, @cluster, @image_name, @image_tag)
RETURNING
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
DELETE FROM workloads
WHERE name = @name
  AND workload_type = @workload_type
  AND namespace = @namespace
  AND cluster = @cluster
RETURNING
    id
;

-- name: ListWorkloadsByImage :many
SELECT *
FROM workloads
WHERE image_name = @image_name
  AND image_tag = @image_tag
ORDER BY
    (name, cluster, updated_at) DESC;

-- name: ListWorkloadsByCluster :many
SELECT *
FROM workloads
WHERE cluster = @cluster
ORDER BY
    (name, namespace, cluster, updated_at) DESC;
