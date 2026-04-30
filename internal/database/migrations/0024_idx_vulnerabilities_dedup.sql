-- +goose Up
-- Support efficient deduplication of alias vs canonical CVE rows in
-- ListWorkloadsForVulnerabilities. The query filters on
-- (image_name, image_tag, package, cve_id) to exclude alias rows when a
-- canonical row already exists for the same workload+package. The existing
-- unique constraint has column order (image_name, image_tag, cve_id, package)
-- which cannot satisfy an equality lookup on package before cve_id.
--
-- Performance trade-off: this is a composite index over four TEXT columns.
-- image_name and package in particular can be long strings (docker registry
-- paths and purl identifiers). The index will be proportionally larger than
-- a single-column index and will add overhead to INSERT and UPDATE on the
-- vulnerabilities table.
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_image_package_cve ON vulnerabilities(image_name, image_tag, package, cve_id);

-- +goose Down
DROP INDEX IF EXISTS idx_vulnerabilities_image_package_cve;
