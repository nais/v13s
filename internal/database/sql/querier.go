// Code generated by sqlc. DO NOT EDIT.

package sql

import (
	"context"
)

type Querier interface {
	Create(ctx context.Context, arg CreateParams) (*Workload, error)
	CreateVulnerabilitySummary(ctx context.Context, arg CreateVulnerabilitySummaryParams) (*VulnerabilitySummary, error)
	ListVulnerabilitySummary(ctx context.Context, arg ListVulnerabilitySummaryParams) ([]*VulnerabilitySummary, error)
	Update(ctx context.Context, arg UpdateParams) (*Workload, error)
	UpdateVulnerabilitySummary(ctx context.Context, arg UpdateVulnerabilitySummaryParams) (*VulnerabilitySummary, error)
}

var _ Querier = (*Queries)(nil)
