// Code generated by sqlc. DO NOT EDIT.
// source: workloads.sql

package sql

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const create = `-- name: Create :one
INSERT INTO
    workloads (name, workload_type, namespace, cluster, image_name, image_tag)
VALUES
    ($1, $2, $3, $4, $5, $6)
RETURNING
    id, name, workload_type, namespace, cluster, image_name, image_tag, created_at, updated_at
`

type CreateParams struct {
	Name         string
	WorkloadType WorkloadType
	Namespace    string
	Cluster      string
	ImageName    string
	ImageTag     string
}

func (q *Queries) Create(ctx context.Context, arg CreateParams) (*Workload, error) {
	row := q.db.QueryRow(ctx, create,
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

const update = `-- name: Update :one
UPDATE workloads
SET
    name = COALESCE($1, name),
    workload_type = COALESCE($2, workload_type),
    namespace = COALESCE($3, namespace),
    cluster = COALESCE($4, cluster),
    image_name = COALESCE($5, image_name),
    image_tag = COALESCE($6, image_tag)
WHERE
    workloads.id = $7
RETURNING
    id, name, workload_type, namespace, cluster, image_name, image_tag, created_at, updated_at
`

type UpdateParams struct {
	Name         *string
	WorkloadType NullWorkloadType
	Namespace    *string
	Cluster      *string
	ImageName    *string
	ImageTag     *string
	ID           pgtype.UUID
}

func (q *Queries) Update(ctx context.Context, arg UpdateParams) (*Workload, error) {
	row := q.db.QueryRow(ctx, update,
		arg.Name,
		arg.WorkloadType,
		arg.Namespace,
		arg.Cluster,
		arg.ImageName,
		arg.ImageTag,
		arg.ID,
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