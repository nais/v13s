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

CREATE TYPE workload_type AS ENUM('deployment')
;

-- tables
CREATE TABLE workloads
(
    id            UUID                     DEFAULT gen_random_uuid() PRIMARY KEY,
    name          TEXT          NOT NULL,
    workload_type workload_type NOT NULL,
    namespace     TEXT          NOT NULL,
    cluster       TEXT          NOT NULL,
    image_name    TEXT          NOT NULL,
    image_tag     TEXT          NOT NULL,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
)
;

CREATE TABLE images
(
    name       TEXT NOT NULL,
    tag        TEXT NOT NULL,
    PRIMARY KEY (name, tag),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
)
;

CREATE TABLE vulnerability_summary
(
    id         UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    image_name TEXT NOT NULL,
    image_tag  TEXT NOT NULL,
    critical   INT  NOT NULL,
    high       INT  NOT NULL,
    medium     INT  NOT NULL,
    low        INT  NOT NULL,
    unassigned INT  NOT NULL,
    risk_score INT  NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
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