-- +goose Up
ALTER TABLE source_refs
    ADD COLUMN image_name TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN image_tag TEXT NOT NULL DEFAULT 'unknown';

UPDATE
    source_refs AS s
SET
    image_name = w.image_name,
    image_tag = w.image_tag
FROM
    workloads AS w
WHERE
    s.workload_id = w.id;

--1. Drop the column
ALTER TABLE source_refs
    DROP COLUMN IF EXISTS workload_id;

WITH keepers AS (
    SELECT DISTINCT ON (source_id)
        source_id,
        id
    FROM
        source_refs
    ORDER BY
        source_id,
        id)
DELETE FROM source_refs
WHERE id NOT IN (
        SELECT
            id
        FROM
            keepers);

--3. Add the constraint
ALTER TABLE source_refs
    ALTER COLUMN image_name DROP DEFAULT,
    ALTER COLUMN image_tag DROP DEFAULT;

ALTER TABLE source_refs
    ADD CONSTRAINT source_id_image_name_image_tag UNIQUE (image_name, image_tag, source_type, source_id);
