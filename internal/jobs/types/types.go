package types

import (
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources/source"
	"github.com/riverqueue/river"
)

const (
	KindAddWorkload         = "add_workload"
	KindDeleteWorkload      = "delete_workload"
	KindFetchImage          = "fetch_image_vulnerabilities"
	KindFetchImageSummary   = "fetch_image_summary"
	KindFinalizeAttestation = "finalize_attestation"
	KindGetAttestation      = "get_attestation"
	KindRemoveFromSource    = "remove_from_source"
	KindUploadAttestation   = "upload_attestation"
	KindUpsertImage         = "upsert_image"
)

type FetchImageSummaryJob struct {
	ImageName       string
	ImageTag        string
	Vulnerabilities []*source.Vulnerability
}

func (f FetchImageSummaryJob) Kind() string { return KindFetchImageSummary }

type FetchImageVulnerabilitiesJob struct {
	ImageName string
	ImageTag  string
}

func (FetchImageVulnerabilitiesJob) Kind() string { return KindFetchImage }

type AddWorkloadJob struct {
	Workload *model.Workload
}

func (AddWorkloadJob) Kind() string { return KindAddWorkload }

type DeleteWorkloadJob struct {
	Workload *model.Workload
}

func (DeleteWorkloadJob) Kind() string { return KindDeleteWorkload }

type RemoveFromSourceJob struct {
	ImageName string `json:"image_name" river:"unique"`
	ImageTag  string `json:"image_tag" river:"unique"`
}

func (RemoveFromSourceJob) Kind() string { return KindRemoveFromSource }

type GetAttestationJob struct {
	ImageName    string
	ImageTag     string
	WorkloadId   pgtype.UUID
	WorkloadType model.WorkloadType
}

func (GetAttestationJob) Kind() string { return KindGetAttestation }

type UpsertImageJob struct {
	Data *ImageVulnerabilityData
}

func (UpsertImageJob) Kind() string { return KindUpsertImage }

func (UpsertImageJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindUpsertImage,
		MaxAttempts: 3,
	}
}

type ImageVulnerabilityData struct {
	ImageName       string
	ImageTag        string
	Source          string
	Vulnerabilities []*source.Vulnerability
	Summary         *source.VulnerabilitySummary
	Workloads       []*sql.ListWorkloadsByImageRow
}

func (i *ImageVulnerabilityData) ToCveSqlParams() []sql.BatchUpsertCveParams {
	params := make([]sql.BatchUpsertCveParams, 0)
	for _, v := range i.Vulnerabilities {
		params = append(params, sql.BatchUpsertCveParams{
			CveID:    v.Cve.Id,
			CveTitle: v.Cve.Title,
			CveDesc:  v.Cve.Description,
			CveLink:  v.Cve.Link,
			Severity: v.Cve.Severity.ToInt32(),
			Refs:     v.Cve.References,
		})
	}
	return params
}

func (i *ImageVulnerabilityData) ToVulnerabilitySummarySqlParams() sql.BatchUpsertVulnerabilitySummaryParams {
	return sql.BatchUpsertVulnerabilitySummaryParams{
		ImageName:  i.ImageName,
		ImageTag:   i.ImageTag,
		Critical:   i.Summary.Critical,
		High:       i.Summary.High,
		Medium:     i.Summary.Medium,
		Low:        i.Summary.Low,
		Unassigned: i.Summary.Unassigned,
		RiskScore:  i.Summary.RiskScore,
	}
}

type UploadAttestationJob struct {
	ImageName   string `river:"unique"`
	ImageTag    string `river:"unique"`
	WorkloadId  pgtype.UUID
	Attestation []byte
}

func (UploadAttestationJob) Kind() string { return KindUploadAttestation }

type FinalizeAttestationJob struct {
	ImageName    string `river:"unique"`
	ImageTag     string `river:"unique"`
	ProcessToken string
}

func (FinalizeAttestationJob) Kind() string { return KindFinalizeAttestation }
