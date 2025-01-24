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
        image_tag = @image_tag
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
    image_tag = @image_tag
WHERE
    cluster = @cluster AND
    namespace = @namespace AND
    workload_type = @workload_type AND
    name = @name
RETURNING
    *
;