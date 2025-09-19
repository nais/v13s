package types

import (
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
)

const KindUpsertImage = "upsert_image"

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
	Vulnerabilities []*sources.Vulnerability
	Summary         *sources.VulnerabilitySummary
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
