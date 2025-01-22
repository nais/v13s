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

-- functions
CREATE
OR REPLACE FUNCTION set_updated_at () RETURNS TRIGGER AS $$
BEGIN NEW.updated_at
= NOW();
RETURN NEW;
END; $$
LANGUAGE plpgsql
;

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
    updated_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
)
;

CREATE TABLE images
(
    name       TEXT NOT NULL,
    tag        TEXT NOT NULL,
    PRIMARY KEY (name, tag),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
)
;

ALTER TABLE workloads
    ADD CONSTRAINT fk_image
        FOREIGN KEY (image_name, image_tag)
        REFERENCES images (name, tag)
        ON DELETE CASCADE;