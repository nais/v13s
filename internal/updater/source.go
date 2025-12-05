package updater

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"golang.org/x/sync/errgroup"
)

type ImageVulnerabilityData struct {
	ImageName       string
	ImageTag        string
	Source          string
	Vulnerabilities []*sources.Vulnerability
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
	// TODO: postgresriver fetch and filter vulnerabilities
	vulnerabilities, err := u.source.GetVulnerabilities(ctx, imageName, imageTag, true)
	if err != nil {
		return nil, err
	}
	u.log.Debugf("Got %d vulnerabilities", len(vulnerabilities))

	// sync suppressed vulnerabilities
	suppressedVulns, err := u.querier.ListSuppressedVulnerabilitiesForImage(ctx, imageName)
	if err != nil {
		return nil, err
	}

	u.log.Debugf("Got %d suppressed vulnerabilities", len(suppressedVulns))
	filteredVulnerabilities := make([]*sources.SuppressedVulnerability, 0)
	for _, s := range suppressedVulns {
		for _, v := range vulnerabilities {
			if v.Cve.Id == s.CveID && v.Package == s.Package && s.Suppressed != v.Suppressed {
				filteredVulnerabilities = append(filteredVulnerabilities, &sources.SuppressedVulnerability{
					ImageName:    imageName,
					ImageTag:     imageTag,
					CveId:        v.Cve.Id,
					Package:      v.Package,
					Suppressed:   s.Suppressed,
					Reason:       s.ReasonText,
					SuppressedBy: s.SuppressedBy,
					State:        vulnerabilitySuppressReasonToState(s.Reason),
					Metadata:     v.Metadata,
				})
			}
		}
	}

	// TODO: postgresriver job to maintain suppressed vulnerabilities
	err = u.source.MaintainSuppressedVulnerabilities(ctx, filteredVulnerabilities)
	if err != nil {
		return nil, err
	}

	// refetch vulnerabilities to get updated suppression states
	// this is just a quick fix, not sure if it will handle all cases
	// timing issue, if source is ready with new data, then we need to refactor the way we do suppressing
	vulnerabilities, err = u.source.GetVulnerabilities(ctx, imageName, imageTag, true)
	if err != nil {
		return nil, err
	}

	// return updated vulnerabilities
	return &ImageVulnerabilityData{
		ImageName:       imageName,
		ImageTag:        imageTag,
		Source:          source.Name(),
		Vulnerabilities: vulnerabilities,
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

func (u *Updater) ToVulnerabilitySqlParams(ctx context.Context, i *ImageVulnerabilityData) []sql.BatchUpsertVulnerabilitiesParams {
	params := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	for _, v := range i.Vulnerabilities {
		severity := v.Cve.Severity.ToInt32()
		severitySince, err := u.DetermineSeveritySince(ctx, i.ImageName, v.Package, v.Cve.Id, severity)
		if err != nil {
			u.log.Errorf("determine severitySince: %v", err)
		}
		batch := sql.BatchUpsertVulnerabilitiesParams{
			ImageName:     i.ImageName,
			ImageTag:      i.ImageTag,
			Package:       v.Package,
			CveID:         v.Cve.Id,
			Source:        i.Source,
			LatestVersion: v.LatestVersion,
			LastSeverity:  severity,
			CvssScore:     v.CvssScore,
		}

		if severitySince != nil {
			batch.SeveritySince = pgtype.Timestamptz{
				Time:  *severitySince,
				Valid: true,
			}
		}
		params = append(params, batch)
	}
	return params
}

func (u *Updater) DetermineSeveritySince(
	ctx context.Context,
	imageName, pkg, cveID string,
	lastSeverity int32,
) (*time.Time, error) {

	earliest, err := u.querier.GetEarliestSeveritySinceForVulnerability(ctx, sql.GetEarliestSeveritySinceForVulnerabilityParams{
		ImageName:    imageName,
		Package:      pkg,
		CveID:        cveID,
		LastSeverity: lastSeverity,
	})
	if err != nil {
		return nil, err
	}

	if earliest.Valid {
		t := earliest.Time.UTC()
		return &t, nil
	}

	now := time.Now().UTC()
	return &now, nil
}

func (i *ImageVulnerabilityData) ToCveSqlParams() []sql.BatchUpsertCveParams {
	params := make([]sql.BatchUpsertCveParams, 0)
	for _, v := range i.Vulnerabilities {
		params = append(params, sql.BatchUpsertCveParams{
			CveID:     v.Cve.Id,
			CveTitle:  v.Cve.Title,
			CveDesc:   v.Cve.Description,
			CveLink:   v.Cve.Link,
			Severity:  v.Cve.Severity.ToInt32(),
			Refs:      v.Cve.References,
			CvssScore: v.CvssScore,
		})
	}
	return params
}
