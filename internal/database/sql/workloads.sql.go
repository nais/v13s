// Code generated by sqlc. DO NOT EDIT.
// source: workloads.sql

package sql

import (
	"context"
)

const createWorkload = `-- name: CreateWorkload :one
INSERT INTO
    workloads (name, workload_type, namespace, cluster, image_name, image_tag)
VALUES
    ($1, $2, $3, $4, $5, $6)
RETURNING
    id, name, workload_type, namespace, cluster, image_name, image_tag, created_at, updated_at
`

type CreateWorkloadParams struct {
	Name         string
	WorkloadType string
	Namespace    string
	Cluster      string
	ImageName    string
	ImageTag     string
}

func (q *Queries) CreateWorkload(ctx context.Context, arg CreateWorkloadParams) (*Workload, error) {
	row := q.db.QueryRow(ctx, createWorkload,
		arg.Name,
		arg.WorkloadType,
		arg.Namespace,
		arg.Cluster,
		arg.ImageName,
		arg.ImageTag,
	)
	var i Workload
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.WorkloadType,
		&i.Namespace,
		&i.Cluster,
		&i.ImageName,
		&i.ImageTag,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return &i, err
}

const deleteWorkload = `-- name: DeleteWorkload :exec
DELETE FROM workloads
WHERE name = $1
  AND workload_type = $2
  AND namespace = $3
  AND cluster = $4
`

type DeleteWorkloadParams struct {
	Name         string
	WorkloadType string
	Namespace    string
	Cluster      string
}

func (q *Queries) DeleteWorkload(ctx context.Context, arg DeleteWorkloadParams) error {
	_, err := q.db.Exec(ctx, deleteWorkload,
		arg.Name,
		arg.WorkloadType,
		arg.Namespace,
		arg.Cluster,
	)
	return err
}

const listWorkloadsByImage = `-- name: ListWorkloadsByImage :many
SELECT id, name, workload_type, namespace, cluster, image_name, image_tag, created_at, updated_at
FROM workloads
WHERE image_name = $1
  AND image_tag = $2
ORDER BY
    (name, cluster, updated_at) DESC
`

type ListWorkloadsByImageParams struct {
	ImageName string
	ImageTag  string
}

func (q *Queries) ListWorkloadsByImage(ctx context.Context, arg ListWorkloadsByImageParams) ([]*Workload, error) {
	rows, err := q.db.Query(ctx, listWorkloadsByImage, arg.ImageName, arg.ImageTag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []*Workload{}
	for rows.Next() {
		var i Workload
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.WorkloadType,
			&i.Namespace,
			&i.Cluster,
			&i.ImageName,
			&i.ImageTag,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, &i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const upsertWorkload = `-- name: UpsertWorkload :exec
INSERT INTO workloads(
    name,
    workload_type,
    namespace,
    cluster,
    image_name,
    image_tag
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
) ON CONFLICT
    ON CONSTRAINT workload_id DO
        UPDATE
    SET
        image_name = $5,
        image_tag = $6,
        updated_at = NOW()
`

type UpsertWorkloadParams struct {
	Name         string
	WorkloadType string
	Namespace    string
	Cluster      string
	ImageName    string
	ImageTag     string
}

func (q *Queries) UpsertWorkload(ctx context.Context, arg UpsertWorkloadParams) error {
	_, err := q.db.Exec(ctx, upsertWorkload,
		arg.Name,
		arg.WorkloadType,
		arg.Namespace,
		arg.Cluster,
		arg.ImageName,
		arg.ImageTag,
	)
	return err
}
