-- +goose Up
CREATE TABLE cve_explanation(
    cve_id TEXT PRIMARY KEY REFERENCES cve(cve_id) ON DELETE CASCADE,
    summary TEXT,
    action TEXT,
    model TEXT,
    prompt_version INT NOT NULL,
    input_hash TEXT NOT NULL,
    source_urls TEXT[] NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ,
    CHECK ((summary IS NULL AND action IS NULL AND model IS NULL AND created_at IS NULL) OR (summary IS NOT NULL AND action IS NOT NULL AND model IS NOT NULL AND created_at IS NOT NULL))
);

-- +goose Down
DROP TABLE cve_explanation;
