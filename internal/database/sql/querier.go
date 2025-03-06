// Code generated by sqlc. DO NOT EDIT.

package sql

import (
	"context"
)

type Querier interface {
	BatchUpdateImageState(ctx context.Context, arg []BatchUpdateImageStateParams) *BatchUpdateImageStateBatchResults
	BatchUpsertCve(ctx context.Context, arg []BatchUpsertCveParams) *BatchUpsertCveBatchResults
	BatchUpsertVulnerabilities(ctx context.Context, arg []BatchUpsertVulnerabilitiesParams) *BatchUpsertVulnerabilitiesBatchResults
	BatchUpsertVulnerabilitySummary(ctx context.Context, arg []BatchUpsertVulnerabilitySummaryParams) *BatchUpsertVulnerabilitySummaryBatchResults
	CountSuppressedVulnerabilities(ctx context.Context, arg CountSuppressedVulnerabilitiesParams) (int64, error)
	CountVulnerabilities(ctx context.Context, arg CountVulnerabilitiesParams) (int64, error)
	CountVulnerabilitiesForImage(ctx context.Context, arg CountVulnerabilitiesForImageParams) (int64, error)
	CreateImage(ctx context.Context, arg CreateImageParams) error
	CreateVulnerabilitySummary(ctx context.Context, arg CreateVulnerabilitySummaryParams) (*VulnerabilitySummary, error)
	CreateWorkload(ctx context.Context, arg CreateWorkloadParams) (*Workload, error)
	GenerateVulnerabilitySummaryForImage(ctx context.Context, arg GenerateVulnerabilitySummaryForImageParams) (*GenerateVulnerabilitySummaryForImageRow, error)
	GetCve(ctx context.Context, cveID string) (*Cve, error)
	GetImage(ctx context.Context, arg GetImageParams) (*Image, error)
	GetImagesScheduledForSync(ctx context.Context) ([]*Image, error)
	GetSuppressedVulnerability(ctx context.Context, arg GetSuppressedVulnerabilityParams) (*SuppressedVulnerability, error)
	GetVulnerability(ctx context.Context, arg GetVulnerabilityParams) (*Vulnerability, error)
	GetVulnerabilitySummary(ctx context.Context, arg GetVulnerabilitySummaryParams) (*GetVulnerabilitySummaryRow, error)
	GetVulnerabilitySummaryForImage(ctx context.Context, arg GetVulnerabilitySummaryForImageParams) (*VulnerabilitySummary, error)
	ListAllSuppressedVulnerabilities(ctx context.Context) ([]*SuppressedVulnerability, error)
	ListAllVulnerabilitySummaries(ctx context.Context, arg ListAllVulnerabilitySummariesParams) ([]*VulnerabilitySummary, error)
	ListSuppressedVulnerabilities(ctx context.Context, arg ListSuppressedVulnerabilitiesParams) ([]*ListSuppressedVulnerabilitiesRow, error)
	ListSuppressedVulnerabilitiesForImage(ctx context.Context, imageName string) ([]*SuppressedVulnerability, error)
	ListVulnerabilities(ctx context.Context, arg ListVulnerabilitiesParams) ([]*ListVulnerabilitiesRow, error)
	ListVulnerabilitiesForImage(ctx context.Context, arg ListVulnerabilitiesForImageParams) ([]*ListVulnerabilitiesForImageRow, error)
	ListVulnerabilitySummaries(ctx context.Context, arg ListVulnerabilitySummariesParams) ([]*ListVulnerabilitySummariesRow, error)
	ListWorkloadsByImage(ctx context.Context, arg ListWorkloadsByImageParams) ([]*Workload, error)
	MarkImagesAsUntracked(ctx context.Context, includedStates []ImageState) error
	MarkImagesForResync(ctx context.Context, arg MarkImagesForResyncParams) error
	ResetDatabase(ctx context.Context) error
	SuppressVulnerability(ctx context.Context, arg SuppressVulnerabilityParams) error
	UpdateImageState(ctx context.Context, arg UpdateImageStateParams) error
	UpdateImageSyncStatus(ctx context.Context, arg UpdateImageSyncStatusParams) error
	UpdateVulnerabilitySummary(ctx context.Context, arg UpdateVulnerabilitySummaryParams) (*VulnerabilitySummary, error)
	UpdateWorkload(ctx context.Context, arg UpdateWorkloadParams) (*Workload, error)
	UpsertWorkload(ctx context.Context, arg UpsertWorkloadParams) error
}

var _ Querier = (*Queries)(nil)
