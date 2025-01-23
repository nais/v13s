// Code generated by sqlc. DO NOT EDIT.

package sql

import (
	"github.com/jackc/pgx/v5/pgtype"
)

type Image struct {
	Name      string
	Tag       string
	CreatedAt pgtype.Timestamptz
	UpdatedAt pgtype.Timestamptz
}

type VulnerabilitySummary struct {
	ID         pgtype.UUID
	ImageName  string
	ImageTag   string
	Critical   int32
	High       int32
	Medium     int32
	Low        int32
	Unassigned int32
	RiskScore  int32
	CreatedAt  pgtype.Timestamptz
	UpdatedAt  pgtype.Timestamptz
}

type Workload struct {
	ID           pgtype.UUID
	Name         string
	WorkloadType string
	Namespace    string
	Cluster      string
	ImageName    string
	ImageTag     string
	CreatedAt    pgtype.Timestamptz
	UpdatedAt    pgtype.Timestamptz
}
