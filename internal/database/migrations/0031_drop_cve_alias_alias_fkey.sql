-- +goose Up
ALTER TABLE cve_alias
    DROP CONSTRAINT IF EXISTS cve_alias_alias_fkey;

-- +goose Down
ALTER TABLE cve_alias
    ADD CONSTRAINT cve_alias_alias_fkey FOREIGN KEY (alias) REFERENCES cve(cve_id) ON DELETE CASCADE;
