-- +goose Up
-- SBOM storage own table so that queries on images
-- do not pull ~34 KB TOAST blobs through the buffer cache.
CREATE TABLE image_sboms(
    image_name TEXT NOT NULL,
    image_tag  TEXT NOT NULL,
    sbom       BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    PRIMARY KEY (image_name, image_tag),
    CONSTRAINT image_sboms_image_fk
        FOREIGN KEY (image_name, image_tag)
        REFERENCES images (name, tag)
        ON DELETE CASCADE
);

ALTER TABLE image_sync_status
    ADD CONSTRAINT fk_image
        FOREIGN KEY (image_name, image_tag)
            REFERENCES images (name, tag)
            ON DELETE CASCADE;

-- +goose Down
ALTER TABLE image_sync_status DROP CONSTRAINT fk_image;
DROP TABLE IF EXISTS image_sboms;
