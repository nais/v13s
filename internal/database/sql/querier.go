// Code generated by sqlc. DO NOT EDIT.

package sql

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

type Querier interface {
	BatchUpsertCve(ctx context.Context, arg []BatchUpsertCveParams) *BatchUpsertCveBatchResults
	BatchUpsertVulnerabilities(ctx context.Context, arg []BatchUpsertVulnerabilitiesParams) *BatchUpsertVulnerabilitiesBatchResults
	CountVulnerabilities(ctx context.Context, arg CountVulnerabilitiesParams) (int64, error)
	CreateImage(ctx context.Context, arg CreateImageParams) error
	CreateVulnerabilitySummary(ctx context.Context, arg CreateVulnerabilitySummaryParams) (*VulnerabilitySummary, error)
	CreateWorkload(ctx context.Context, arg CreateWorkloadParams) (*Workload, error)
	GetCve(ctx context.Context, cveID string) (*Cve, error)
	GetImage(ctx context.Context, arg GetImageParams) (*Image, error)
	GetImagesScheduledForSync(ctx context.Context) ([]*Image, error)
	GetSuppressedVulnerability(ctx context.Context, arg GetSuppressedVulnerabilityParams) (*SuppressedVulnerability, error)
	GetVulnerability(ctx context.Context, arg GetVulnerabilityParams) (*Vulnerability, error)
	GetVulnerabilitySummary(ctx context.Context, arg GetVulnerabilitySummaryParams) (*GetVulnerabilitySummaryRow, error)
	ListAllVulnerabilitySummaries(ctx context.Context, arg ListAllVulnerabilitySummariesParams) ([]*VulnerabilitySummary, error)
	ListSuppressedVulnerabilitiesForImage(ctx context.Context, arg ListSuppressedVulnerabilitiesForImageParams) ([]*SuppressedVulnerability, error)
	ListVulnerabilities(ctx context.Context, arg ListVulnerabilitiesParams) ([]*ListVulnerabilitiesRow, error)
	ListVulnerabilitySummaries(ctx context.Context, arg ListVulnerabilitySummariesParams) ([]*ListVulnerabilitySummariesRow, error)
	MarkImagesForResync(ctx context.Context, thresholdTime pgtype.Timestamptz) error
	ResetDatabase(ctx context.Context) error
	SuppressVulnerability(ctx context.Context, arg SuppressVulnerabilityParams) error
	UpdateImageState(ctx context.Context, arg UpdateImageStateParams) error
	UpdateVulnerabilitySummary(ctx context.Context, arg UpdateVulnerabilitySummaryParams) (*VulnerabilitySummary, error)
	UpdateWorkload(ctx context.Context, arg UpdateWorkloadParams) (*Workload, error)
	UpsertVulnerabilitySummary(ctx context.Context, arg UpsertVulnerabilitySummaryParams) error
	UpsertWorkload(ctx context.Context, arg UpsertWorkloadParams) error
}

var _ Querier = (*Queries)(nil)
