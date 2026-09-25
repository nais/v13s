-- +goose Up
CREATE TABLE cve_kev_source (
    cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    known_ransomware_use BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cve_id, source)
);

INSERT INTO cve_kev_source (cve_id, source, known_ransomware_use)
SELECT
    cve_id,
    'cisa',
    known_ransomware_use
FROM
    cve
WHERE
    has_kev_entry = TRUE;

-- +goose Down
DROP TABLE IF EXISTS cve_kev_source;
