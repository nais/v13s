// Code generated by sqlc. DO NOT EDIT.

package sql

import (
	"github.com/jackc/pgx/v5/pgtype"
	typeext "github.com/nais/v13s/internal/database/typeext"
)

type Cwe struct {
	CweID     string
	CweTitle  string
	CweDesc   string
	CweLink   string
	Severity  int32
	CreatedAt pgtype.Timestamptz
	UpdatedAt pgtype.Timestamptz
}

type Image struct {
	Name      string
	Tag       string
	Metadata  typeext.MapStringString
	CreatedAt pgtype.Timestamptz
	UpdatedAt pgtype.Timestamptz
}

type Vulnerability struct {
	ID        pgtype.UUID
	ImageName string
	ImageTag  string
	Package   string
	CweID     string
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
