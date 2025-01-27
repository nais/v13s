-- name: BatchUpsertVulnerabilities :batchexec
INSERT INTO vulnerabilities(image_name,
                                  image_tag,
                                  package,
                                  cwe_id)

VALUES (@image_name,
        @image_tag,
        @package,
        @cwe_id)
ON CONFLICT DO NOTHING
;

-- name: BatchUpsertCwe :batchexec
INSERT INTO cwe(cwe_id,
                cwe_title,
                cwe_desc,
                cwe_link,
                severity)
VALUES (@cwe_id,
        @cwe_title,
        @cwe_desc,
        @cwe_link,
        @severity)
ON CONFLICT (cwe_id)
    DO
        UPDATE
    SET cwe_title = @cwe_title,
        cwe_desc = @cwe_desc,
        cwe_link = @cwe_link,
        severity = @severity
;

-- name: GetCwe :one
SELECT * FROM cwe WHERE cwe_id = @cwe_id;



-- name: GetVulnerability :one
SELECT * FROM vulnerabilities WHERE image_name = @image_name AND image_tag = @image_tag AND package = @package AND cwe_id = @cwe_id;
