-- +goose Up
-- One row per (package, version), not per image: a registry's published hash
-- for a given version is global, so images sharing that version share a row.
CREATE TABLE package_registry_hashes(
    package TEXT NOT NULL,
    registry_hash TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL,
    resolver TEXT NOT NULL,
    resolved_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (package)
);

-- +goose Down
DROP TABLE IF EXISTS package_registry_hashes;
