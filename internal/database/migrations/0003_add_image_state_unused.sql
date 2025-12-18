-- +goose Up
ALTER TYPE image_state
    ADD VALUE 'unused';
