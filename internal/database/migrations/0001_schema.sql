-- +goose Up
-- Grant permissions in GCP if the role cloudsqlsuperuser exists
-- +goose StatementBegin
DO
$$
BEGIN
   IF
EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE  rolname = 'cloudsqlsuperuser') THEN
        GRANT ALL ON SCHEMA public TO cloudsqlsuperuser;
END IF;
END
$$;

-- +goose StatementEnd
-- extensions
CREATE
EXTENSION fuzzystrmatch;

-- tables
CREATE TABLE workloads
(
    id            UUID                     DEFAULT gen_random_uuid() PRIMARY KEY,
    name          TEXT                                               NOT NULL,
    workload_type TEXT                                               NOT NULL,
    namespace     TEXT                                               NOT NULL,
    cluster       TEXT                                               NOT NULL,
    CONSTRAINT workload_id UNIQUE (name, workload_type, namespace, cluster),
    image_name    TEXT                                               NOT NULL,
    image_tag     TEXT                                               NOT NULL,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()             NOT NULL
)
;

CREATE TYPE image_state AS ENUM ('initialized','updated','queued', 'failed', 'outdated');

-- TODO: consider adding the workload to the image table instead of the other way around
CREATE TABLE images
(
    name       TEXT        NOT NULL,
    tag        TEXT        NOT NULL,
    PRIMARY KEY (name, tag),
    metadata   JSONB       NOT NULL     DEFAULT '{}'::jsonb,
    state      image_state NOT NULL     DEFAULT 'initialized',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
)
;

CREATE TABLE vulnerability_summary
(
    id         UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    image_name TEXT                                               NOT NULL,
    image_tag  TEXT                                               NOT NULL,
    critical   INT                                                NOT NULL,
    high       INT                                                NOT NULL,
    medium     INT                                                NOT NULL,
    low        INT                                                NOT NULL,
    unassigned INT                                                NOT NULL,
    risk_score INT                                                NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()             NOT NULL,
    CONSTRAINT image_name_tag UNIQUE (image_name, image_tag)
)
;

-- TODO: consider adding a type for severity
-- TODO: consider adding a table for package and cwe
CREATE TABLE vulnerabilities
(
    id         UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    image_name TEXT                                               NOT NULL,
    image_tag  TEXT                                               NOT NULL,
    package    TEXT                                               NOT NULL,
    cwe_id     TEXT                                               NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()             NOT NULL,
    CONSTRAINT image_name_tag_cwe_id_package UNIQUE (image_name, image_tag, cwe_id, package)
)
;

CREATE TYPE vulnerability_suppress_reason AS ENUM ('in_triage', 'resolved', 'false_positive', 'not_affected', 'not_set');

CREATE TABLE suppressed_vulnerabilities
(
    id          UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    image_name  TEXT                                               NOT NULL,
    package     TEXT                                               NOT NULL,
    cwe_id      TEXT                                               NOT NULL,
    suppressed  BOOLEAN                                            NOT NULL DEFAULT FALSE,
    reason      vulnerability_suppress_reason                      NOT NULL DEFAULT 'not_set',
    reason_text TEXT                                               NOT NULL DEFAULT '',
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()             NOT NULL,
    CONSTRAINT image_name_package_cwe_id UNIQUE (image_name, package, cwe_id)
)
;

-- TODO: pluralize this table name?
CREATE TABLE cwe
(
    cwe_id     TEXT                                               NOT NULL,
    PRIMARY KEY (cwe_id),
    cwe_title  TEXT                                               NOT NULL,
    cwe_desc   TEXT                                               NOT NULL,
    cwe_link   TEXT                                               NOT NULL,
    severity   INT                                                NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()             NOT NULL
)
;

ALTER TABLE workloads
    ADD CONSTRAINT fk_image
        FOREIGN KEY (image_name, image_tag)
            REFERENCES images (name, tag)
            ON DELETE CASCADE;

ALTER TABLE vulnerability_summary
    ADD CONSTRAINT fk_image
        FOREIGN KEY (image_name, image_tag)
            REFERENCES images (name, tag)
            ON DELETE CASCADE;

ALTER TABLE vulnerabilities
    ADD CONSTRAINT fk_image
        FOREIGN KEY (image_name, image_tag)
            REFERENCES images (name, tag)
            ON DELETE CASCADE;

ALTER TABLE vulnerabilities
    ADD CONSTRAINT fk_cwe
        FOREIGN KEY (cwe_id)
            REFERENCES cwe (cwe_id)
            ON DELETE CASCADE;
