-- name: CreateImage :exec
INSERT INTO images(
    name,
    tag,
    metadata,
    sbom_processing_started_at)
VALUES (
    @name,
    @tag,
    COALESCE(
        @metadata, '{}' ::JSONB),
    NOW())
ON CONFLICT
    DO NOTHING;

-- name: UpdateImage :exec
UPDATE
    images
SET
    metadata = COALESCE(@metadata, '{}'::JSONB),
    updated_at = NOW()
WHERE
    name = @name
    AND tag = @tag;

-- name: GetImage :one
SELECT
    *
FROM
    images
WHERE
    name = @name
    AND tag = @tag;

-- name: GetImagesScheduledForSync :many
SELECT
    *
FROM
    images
WHERE
    ready_for_resync_at IS NOT NULL
    AND ready_for_resync_at <= NOW()
    AND state IN ('initialized', 'resync')
ORDER BY
    updated_at DESC;

-- name: UpdateImageState :execrows
UPDATE
    images
SET
    state = @state,
    ready_for_resync_at = @ready_for_resync_at,
    sbom_processing_started_at = CASE WHEN @state::image_state IN ('resync', 'initialized')
        AND state IN ('resync', 'initialized')
        AND sbom_processing_started_at IS NOT NULL THEN
        sbom_processing_started_at
    WHEN @state::image_state IN ('resync', 'initialized') THEN
        NOW()
    WHEN @state::image_state = 'updated' THEN
        sbom_processing_started_at
    ELSE
        NULL
    END,
    updated_at = NOW()
WHERE
    name = @name
    AND tag = @tag;

-- name: BatchUpdateImageState :batchexec
UPDATE
    images
SET
    state = @state,
    ready_for_resync_at = NULL,
    updated_at = NOW()
WHERE
    name = @name
    AND tag = @tag;

-- name: MarkImagesAsUntracked :execrows
UPDATE
    images
SET
    state = 'untracked',
    updated_at = NOW()
WHERE
    images.state = ANY (@included_states::image_state[])
    AND images.updated_at < @threshold_time
    AND images.ready_for_resync_at IS NULL
    AND EXISTS (
        SELECT
            1
        FROM
            workloads
        WHERE
            image_name = images.name
            AND image_tag = images.tag);

-- name: MarkUnusedImages :execrows
UPDATE
    images
SET
    state = 'unused',
    updated_at = NOW()
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            workloads
        WHERE
            image_name = images.name
            AND image_tag = images.tag)
    AND images.updated_at < @threshold_time
    AND images.state != 'unused'
    AND images.state != ANY (@excluded_states::image_state[]);

-- name: ListUnusedImages :many
SELECT
    name,
    tag
FROM
    images
WHERE
    NOT EXISTS (
        SELECT
            1
        FROM
            workloads
        WHERE
            image_name = images.name
            AND image_tag = images.tag)
    AND (sqlc.narg('name')::TEXT IS NULL
        OR name = sqlc.narg('name')::TEXT)
ORDER BY
    updated_at;

-- name: MarkImagesForResync :exec
UPDATE
    images
SET
    state = 'resync',
    ready_for_resync_at = NOW(),
    sbom_processing_started_at = NOW(),
    updated_at = NOW()
FROM
    workloads w
WHERE
    images.name = w.image_name
    AND images.tag = w.image_tag
    AND images.updated_at < @threshold_time
    AND images.state != 'resync'
    AND images.state != ANY (@excluded_states::image_state[])
    AND w.state != 'unrecoverable';

-- name: MarkUntrackedImagesForResync :execrows
UPDATE
    images
SET
    state = 'resync',
    ready_for_resync_at = NOW(),
    sbom_processing_started_at = NOW(),
    updated_at = NOW()
WHERE
    state = 'untracked'
    AND EXISTS (
        SELECT
            1
        FROM
            workloads
        WHERE
            image_name = images.name
            AND image_tag = images.tag);

-- name: UpdateImageSyncStatus :exec
INSERT INTO image_sync_status(
    image_name,
    image_tag,
    status_code,
    reason,
    source)
VALUES (
    @image_name,
    @image_tag,
    @status_code,
    @reason,
    @source)
ON CONFLICT (
    image_name,
    image_tag)
    DO UPDATE SET
        status_code = @status_code,
        reason = @reason,
        updated_at = NOW();

-- name: DeleteUnusedImages :one
WITH candidates AS (
    SELECT
        i.name,
        i.tag
    FROM
        images i
    WHERE
        i.state = 'unused'
        AND i.updated_at < @unused_before
        AND NOT EXISTS (
            SELECT
                1
            FROM
                workloads w
            WHERE
                w.image_name = i.name
                AND w.image_tag = i.tag)
        ORDER BY
            i.updated_at
        LIMIT @batch_size
        FOR UPDATE
            SKIP LOCKED
),
vulnerability_count AS (
    SELECT
        COUNT(*) AS count
    FROM
        vulnerabilities v
        JOIN candidates c ON v.image_name = c.name
            AND v.image_tag = c.tag
),
deleted_sync_status AS (
    DELETE FROM image_sync_status s USING candidates c
WHERE s.image_name = c.name
    AND s.image_tag = c.tag), deleted_images AS (
    DELETE FROM images i USING candidates c
WHERE i.name = c.name
    AND i.tag = c.tag
RETURNING
    i.name
)
SELECT
    (
        SELECT
            COUNT(*)
        FROM
            deleted_images)::BIGINT AS deleted_images,
(
            SELECT
                count
            FROM
                vulnerability_count)::BIGINT AS deleted_vulnerabilities;
