-- name: GetPackagesNeedingRegistryHashResolution :many
SELECT DISTINCT
    v.package
FROM
    vulnerabilities v
    LEFT JOIN package_registry_hashes h ON h.package = v.package
WHERE
    v.package != ''
    AND h.package IS NULL
ORDER BY
    v.package;

-- name: BulkUpsertPackageRegistryHashes :execrows
INSERT INTO package_registry_hashes(package, registry_hash, hash_algorithm, resolver, resolved_at)
SELECT
    unnest(@packages::TEXT[]),
    unnest(@registry_hashes::TEXT[]),
    unnest(@hash_algorithms::TEXT[]),
    unnest(@resolvers::TEXT[]),
    NOW()
ON CONFLICT (package)
    DO UPDATE SET
        registry_hash = excluded.registry_hash,
        hash_algorithm = excluded.hash_algorithm,
        resolver = excluded.resolver,
        resolved_at = excluded.resolved_at;

-- name: GetPackageRegistryHashes :many
SELECT
    package,
    registry_hash,
    hash_algorithm,
    resolver,
    resolved_at
FROM
    package_registry_hashes
WHERE
    package = ANY (@packages::TEXT[]);
