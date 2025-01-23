// Code generated by sqlc. DO NOT EDIT.

package sql

import (
	"context"
)

type Querier interface {
	CreateImage(ctx context.Context, arg CreateImageParams) (*Image, error)
	CreateVulnerabilitySummary(ctx context.Context, arg CreateVulnerabilitySummaryParams) (*VulnerabilitySummary, error)
	CreateWorkload(ctx context.Context, arg CreateWorkloadParams) (*Workload, error)
	GetVulnerabilitySummary(ctx context.Context, arg GetVulnerabilitySummaryParams) (*GetVulnerabilitySummaryRow, error)
	ListAllVulnerabilitySummaries(ctx context.Context, arg ListAllVulnerabilitySummariesParams) ([]*VulnerabilitySummary, error)
	ListVulnerabilitySummaries(ctx context.Context, arg ListVulnerabilitySummariesParams) ([]*ListVulnerabilitySummariesRow, error)
	ResetDatabase(ctx context.Context) error
	UpdateVulnerabilitySummary(ctx context.Context, arg UpdateVulnerabilitySummaryParams) (*VulnerabilitySummary, error)
	UpdateWorkload(ctx context.Context, arg UpdateWorkloadParams) (*Workload, error)
}

var _ Querier = (*Queries)(nil)
