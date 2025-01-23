// Code generated by sqlc. DO NOT EDIT.

package sql

import (
	"database/sql/driver"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
)

type WorkloadType string

const (
	WorkloadTypeDeployment WorkloadType = "deployment"
)

func (e *WorkloadType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = WorkloadType(s)
	case string:
		*e = WorkloadType(s)
	default:
		return fmt.Errorf("unsupported scan type for WorkloadType: %T", src)
	}
	return nil
}

type NullWorkloadType struct {
	WorkloadType WorkloadType
	Valid        bool // Valid is true if WorkloadType is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullWorkloadType) Scan(value interface{}) error {
	if value == nil {
		ns.WorkloadType, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.WorkloadType.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullWorkloadType) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.WorkloadType), nil
}

func (e WorkloadType) Valid() bool {
	switch e {
	case WorkloadTypeDeployment:
		return true
	}
	return false
}

func AllWorkloadTypeValues() []WorkloadType {
	return []WorkloadType{
		WorkloadTypeDeployment,
	}
}

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
	WorkloadType WorkloadType
	Namespace    string
	Cluster      string
	ImageName    string
	ImageTag     string
	CreatedAt    pgtype.Timestamptz
	UpdatedAt    pgtype.Timestamptz
}
