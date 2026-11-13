-- name: ListImagePackageTypes :many
SELECT DISTINCT
    split_part(split_part(package, '/', 1), ':', 2)::TEXT AS package_type
FROM
    vulnerabilities
WHERE
    image_name = sqlc.arg('image_name')::TEXT
    AND image_tag = sqlc.arg('image_tag')::TEXT
    AND package ~ '^pkg:[a-z][a-z0-9.+-]*/'
ORDER BY
    package_type;
