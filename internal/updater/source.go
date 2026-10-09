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
		if ctx.Err() != nil {
			break
		}
		image := img
		g.Go(func() error {
			// g.Go may have waited for a free slot, so the batch can have ended since the check above.
			if err := ctx.Err(); err != nil {
				return err
			}
			ctxTimeout, cancel := context.WithTimeout(ctx, 4*time.Minute)
			defer cancel()

			// TODO: we havent updated the db yet so probably need to use another state than updated?
			return SyncImage(ctxTimeout, image.Name, image.Tag, u.source.Name(), func(ctx context.Context) error {
				u.log.Debug("update image")

				imageData, err := u.fetchVulnerabilityData(ctx, image.Name, image.Tag, u.source)
				if err != nil {
					return err
				}

				select {
				case ch <- imageData:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
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

	// Only sync and refetch when a suppression differs; otherwise the first fetch is already current.
	if len(filteredVulnerabilities) > 0 {
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

// SeveritySinceKey identifies a finding across the tags of an image.
type SeveritySinceKey struct {
	ImageName    string
	Package      string
	CveID        string
	LastSeverity int32
}

// DetermineSeveritySince returns, for every finding in images, when it reached
// its current severity, looked up in one query for the whole batch.
func (u *Updater) DetermineSeveritySince(ctx context.Context, images []*ImageVulnerabilityData) (map[SeveritySinceKey]time.Time, error) {
	params := sql.ListEarliestSeveritySinceParams{}
	for _, i := range images {
		for _, v := range i.Vulnerabilities {
			params.ImageNames = append(params.ImageNames, i.ImageName)
			params.Packages = append(params.Packages, v.Package)
			params.CveIds = append(params.CveIds, v.Cve.Id)
			params.LastSeverities = append(params.LastSeverities, v.Cve.Severity.ToInt32())
		}
	}
	since := make(map[SeveritySinceKey]time.Time, len(params.ImageNames))
	if len(params.ImageNames) == 0 {
		return since, nil
	}

	rows, err := u.querier.ListEarliestSeveritySince(ctx, params)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for _, row := range rows {
		key := SeveritySinceKey{ImageName: row.ImageName, Package: row.Package, CveID: row.CveID, LastSeverity: row.LastSeverity}
		since[key] = now
		if row.EarliestSeveritySince.Valid {
			since[key] = row.EarliestSeveritySince.Time.UTC()
		}
	}
	return since, nil
}

func (i *ImageVulnerabilityData) ToVulnerabilitySqlParams(since map[SeveritySinceKey]time.Time) []sql.BatchUpsertVulnerabilitiesParams {
	params := make([]sql.BatchUpsertVulnerabilitiesParams, 0, len(i.Vulnerabilities))
	for _, v := range i.Vulnerabilities {
		severity := v.Cve.Severity.ToInt32()
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
		if ts, ok := since[SeveritySinceKey{ImageName: i.ImageName, Package: v.Package, CveID: v.Cve.Id, LastSeverity: severity}]; ok {
			batch.SeveritySince = pgtype.Timestamptz{Time: ts, Valid: true}
		}
		params = append(params, batch)
	}
	return params
}

func (i *ImageVulnerabilityData) ToCveSqlParams() []sql.BatchUpsertCveParams {
	params := make([]sql.BatchUpsertCveParams, 0)
	for _, v := range i.Vulnerabilities {
		params = append(params, sql.BatchUpsertCveParams{
			CveID:          v.Cve.Id,
			CveTitle:       v.Cve.Title,
			CveDesc:        v.Cve.Description,
			CveLink:        v.Cve.Link,
			Severity:       v.Cve.Severity.ToInt32(),
			Refs:           v.Cve.References,
			CvssScore:      v.CvssScore,
			EpssScore:      v.EpssScore,
			EpssPercentile: v.EpssPercentile,
		})
	}
	return params
}

func (i *ImageVulnerabilityData) ToCveAliasSqlParams() []sql.BatchUpsertCveAliasParams {
	params := make([]sql.BatchUpsertCveAliasParams, 0)
	for _, v := range i.Vulnerabilities {
		for id, alias := range v.Cve.References {
			params = append(params, sql.BatchUpsertCveAliasParams{
				Alias:          alias,
				CanonicalCveID: id,
			})
		}
	}
	return params
}
