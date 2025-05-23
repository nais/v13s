package updater

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
)

type ImageVulnerabilityData struct {
	ImageName       string
	ImageTag        string
	Source          string
	Vulnerabilities []*sources.Vulnerability
	Summary         *sources.VulnerabilitySummary
}

func (u *Updater) FetchVulnerabilityDataForImages(ctx context.Context, images []*sql.Image, limit int, ch chan<- *ImageVulnerabilityData) error {
	var g errgroup.Group
	g.SetLimit(limit) // limit concurrent goroutines

	for _, img := range images {
		image := img
		g.Go(func() error {
			ctxTimeout, cancel := context.WithTimeout(ctx, 4*time.Minute)
			defer cancel()

			// TODO: we havent updated the db yet so probably need to use another state than updated?
			return SyncImage(ctxTimeout, image.Name, image.Tag, u.source.Name(), func(ctx context.Context) error {
				u.log.Debug("update image")

				imageData, err := u.fetchVulnerabilityData(ctx, image.Name, image.Tag, u.source)
				if err != nil {
					return err
				}

				ch <- imageData
				return nil
			})
		})
	}

	return g.Wait()
}

func (u *Updater) fetchVulnerabilityData(ctx context.Context, imageName string, imageTag string, source sources.Source) (*ImageVulnerabilityData, error) {
	findings, err := u.source.GetVulnerabilities(ctx, imageName, imageTag, true)
	if err != nil {
		return nil, err
	}
	u.log.Debugf("Got %d findings", len(findings))

	// sync suppressed vulnerabilities
	suppressedVulns, err := u.querier.ListSuppressedVulnerabilitiesForImage(ctx, imageName)
	if err != nil {
		return nil, err
	}

	u.log.Debugf("Got %d suppressed vulnerabilities", len(suppressedVulns))
	filteredFindings := make([]*sources.SuppressedVulnerability, 0)
	for _, s := range suppressedVulns {
		for _, f := range findings {
			if f.Cve.Id == s.CveID && f.Package == s.Package && s.Suppressed != f.Suppressed {
				filteredFindings = append(filteredFindings, &sources.SuppressedVulnerability{
					ImageName:    imageName,
					ImageTag:     imageTag,
					CveId:        f.Cve.Id,
					Package:      f.Package,
					Suppressed:   s.Suppressed,
					Reason:       s.ReasonText,
					SuppressedBy: s.SuppressedBy,
					State:        vulnerabilitySuppressReasonToState(s.Reason),
					Metadata:     f.Metadata,
				})
			}
		}
	}

	// TODO: We have to wait for the analysis to be done before we can update summary
	err = u.source.MaintainSuppressedVulnerabilities(ctx, filteredFindings)
	if err != nil {
		return nil, err
	}

	summary, err := u.source.GetVulnerabilitySummary(ctx, imageName, imageTag)
	if err != nil {
		return nil, err
	}

	return &ImageVulnerabilityData{
		ImageName:       imageName,
		ImageTag:        imageTag,
		Source:          source.Name(),
		Vulnerabilities: findings,
		Summary:         summary,
	}, nil
}

func vulnerabilitySuppressReasonToState(reason sql.VulnerabilitySuppressReason) string {
	switch reason {
	case sql.VulnerabilitySuppressReasonFalsePositive:
		return "FALSE_POSITIVE"
	case sql.VulnerabilitySuppressReasonInTriage:
		return "IN_TRIAGE"
	case sql.VulnerabilitySuppressReasonNotAffected:
		return "NOT_AFFECTED"
	case sql.VulnerabilitySuppressReasonResolved:
		return "RESOLVED"
	default:
		return "NOT_SET"
	}
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

func (i *ImageVulnerabilityData) ToVulnerabilitySqlParams() []sql.BatchUpsertVulnerabilitiesParams {
	params := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	for _, v := range i.Vulnerabilities {
		params = append(params, sql.BatchUpsertVulnerabilitiesParams{
			ImageName:     i.ImageName,
			ImageTag:      i.ImageTag,
			Package:       v.Package,
			CveID:         v.Cve.Id,
			Source:        i.Source,
			LatestVersion: v.LatestVersion,
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
