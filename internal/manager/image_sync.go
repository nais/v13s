package manager

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const KindSyncImage = "sync_image"

type SyncImageJob struct {
	ImageName string
	ImageTag  string
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

type Workload struct {
	ID        pgtype.UUID
	Cluster   string
	Namespace string
	Name      string
	Type      string
}

func (SyncImageJob) Kind() string { return KindSyncImage }

func (SyncImageJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindSyncImage,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,            // avoid duplicate jobs for same image
			ByPeriod: 2 * time.Minute, // throttle re-syncs
		},
		MaxAttempts: 3,
	}
}

type SyncImageWorker struct {
	db        sql.Querier
	source    sources.Source
	log       logrus.FieldLogger
	jobClient job.Client
	river.WorkerDefaults[SyncImageJob]
}

func (s *SyncImageWorker) Work(ctx context.Context, job *river.Job[SyncImageJob]) error {
	img := job.Args

	s.log.Infof("syncing vulnerabilities for %s:%s", img.ImageName, img.ImageTag)

	data, err := s.fetchVulnerabilityData(ctx, img.ImageName, img.ImageTag, s.source)
	if err != nil {
		s.log.WithError(err).Error("fetch failed")
		return err
	}

	if err := s.upsertBatch(ctx, []*ImageVulnerabilityData{data}); err != nil {
		return err
	}

	recordOutput(ctx, JobStatusImageSynced)
	return nil
}

func (s *SyncImageWorker) fetchVulnerabilityData(ctx context.Context, imageName string, imageTag string, source sources.Source) (*ImageVulnerabilityData, error) {
	vulnerabilities, err := s.source.GetVulnerabilities(ctx, imageName, imageTag, true)
	if err != nil {
		return nil, err
	}
	s.log.Debugf("Got %d vulnerabilities", len(vulnerabilities))

	// sync suppressed vulnerabilities
	suppressedVulns, err := s.db.ListSuppressedVulnerabilitiesForImage(ctx, imageName)
	if err != nil {
		return nil, err
	}

	s.log.Debugf("Got %d suppressed vulnerabilities", len(suppressedVulns))
	filteredVulnerabilities := make([]*sources.SuppressedVulnerability, 0)
	for _, sup := range suppressedVulns {
		for _, v := range vulnerabilities {
			if v.Cve.Id == sup.CveID && v.Package == sup.Package && sup.Suppressed != v.Suppressed {
				filteredVulnerabilities = append(filteredVulnerabilities, &sources.SuppressedVulnerability{
					ImageName:    imageName,
					ImageTag:     imageTag,
					CveId:        v.Cve.Id,
					Package:      v.Package,
					Suppressed:   sup.Suppressed,
					Reason:       sup.ReasonText,
					SuppressedBy: sup.SuppressedBy,
					State:        vulnerabilitySuppressReasonToState(sup.Reason),
					Metadata:     v.Metadata,
				})
			}
		}
	}

	err = s.source.MaintainSuppressedVulnerabilities(ctx, filteredVulnerabilities)
	if err != nil {
		return nil, err
	}

	summary, err := s.source.GetVulnerabilitySummary(ctx, imageName, imageTag)
	if err != nil {
		return nil, err
	}

	workloads, err := s.db.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: imageName,
		ImageTag:  imageTag,
	})
	if err != nil {
		return nil, err
	}

	return &ImageVulnerabilityData{
		ImageName:       imageName,
		ImageTag:        imageTag,
		Source:          source.Name(),
		Vulnerabilities: vulnerabilities,
		Summary:         summary,
		Workloads:       workloads,
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

func (s *SyncImageWorker) upsertBatch(ctx context.Context, batch []*ImageVulnerabilityData) error {
	if len(batch) == 0 {
		return nil
	}
	countError := 0
	errs := make([]error, 0)

	imageStates := make([]sql.BatchUpdateImageStateParams, 0)
	cves := make([]sql.BatchUpsertCveParams, 0)
	vulns := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	summaries := make([]sql.BatchUpsertVulnerabilitySummaryParams, 0)

	for _, i := range batch {
		cves = append(cves, i.ToCveSqlParams()...)
		v, err := ToVulnerabilitySqlParams(ctx, s.db, i)
		if err != nil {
			countError++
			errs = append(errs, err)
			continue
		}
		vulns = append(vulns, v...)
		summaries = append(summaries, i.ToVulnerabilitySummarySqlParams())
		imageStates = append(imageStates, sql.BatchUpdateImageStateParams{
			State: sql.ImageStateUpdated,
			Name:  i.ImageName,
			Tag:   i.ImageTag,
		})

		metrics.SetWorkloadMetrics(i.Workloads, i.Summary)
	}

	sortCveParams(cves)
	sortVulnerabilityParams(vulns)

	start := time.Now()
	var batchErr error
	s.db.BatchUpsertCve(ctx, cves).Exec(func(i int, err error) {
		if err != nil {
			s.log.WithError(err).Debug("failed to batch upsert cves")
			batchErr = err
			countError++
			errs = append(errs, err)
		}
	})
	upserted := len(cves) - countError
	s.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   upserted,
		"num_errors": countError,
	}).Infof("upserted batch of cves")

	start = time.Now()
	countError = 0
	s.db.BatchUpsertVulnerabilities(ctx, vulns).Exec(func(i int, err error) {
		if err != nil {
			s.log.WithError(err).Debug("failed to batch upsert vulnerabilities")
			batchErr = err
			countError++
			errs = append(errs, err)
		}
	})
	upserted = len(vulns) - countError
	s.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   upserted,
		"num_errors": countError,
	}).Infof("upserted batch of vulnerabilities")

	start = time.Now()
	countError = 0
	s.db.BatchUpsertVulnerabilitySummary(ctx, summaries).Exec(func(i int, err error) {
		if err != nil {
			s.log.WithError(err).Debug("failed to batch upsert vulnerability summary")
			batchErr = err
			countError++
			errs = append(errs, err)
		}
	})
	upserted = len(summaries) - countError
	s.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   upserted,
		"num_errors": countError,
	}).Infof("upserted batch of summaries")

	if len(errs) == 0 {
		start = time.Now()
		s.db.BatchUpdateImageState(ctx, imageStates).Exec(func(i int, err error) {
			if err != nil {
				s.log.WithError(err).Debug("failed to batch update image state")
				batchErr = err
				countError++
				errs = append(errs, err)
			}
		})
		s.log.WithError(batchErr).WithFields(logrus.Fields{
			"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
			"num_rows":   upserted,
			"num_errors": countError,
		}).Infof("upserted batch of image states (updated)")
		return nil
	}
	return fmt.Errorf("%d countError occurred during batch upsert: %v", len(errs), errs)
}

func ToVulnerabilitySqlParams(ctx context.Context, db sql.Querier, i *ImageVulnerabilityData) ([]sql.BatchUpsertVulnerabilitiesParams, error) {
	params := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	for _, v := range i.Vulnerabilities {
		severity := v.Cve.Severity.ToInt32()
		severitySince, err := DetermineSeveritySince(ctx, db, i.ImageName, v.Package, v.Cve.Id, severity)
		if err != nil {
			return nil, err
		}
		batch := sql.BatchUpsertVulnerabilitiesParams{
			ImageName:     i.ImageName,
			ImageTag:      i.ImageTag,
			Package:       v.Package,
			CveID:         v.Cve.Id,
			Source:        i.Source,
			LatestVersion: v.LatestVersion,
			LastSeverity:  severity,
		}

		if severitySince != nil {
			batch.SeveritySince = pgtype.Timestamptz{
				Time:  *severitySince,
				Valid: true,
			}
		}
		params = append(params, batch)
	}
	return params, nil
}

func sortCveParams(params []sql.BatchUpsertCveParams) {
	slices.SortFunc(params, func(a, b sql.BatchUpsertCveParams) int {
		return strings.Compare(a.CveID, b.CveID)
	})
}

func sortVulnerabilityParams(params []sql.BatchUpsertVulnerabilitiesParams) {
	slices.SortFunc(params, func(a, b sql.BatchUpsertVulnerabilitiesParams) int {
		if a.ImageName != b.ImageName {
			return strings.Compare(a.ImageName, b.ImageName)
		}
		if a.ImageTag != b.ImageTag {
			return strings.Compare(a.ImageTag, b.ImageTag)
		}
		if a.Package != b.Package {
			return strings.Compare(a.Package, b.Package)
		}
		return strings.Compare(a.CveID, b.CveID)
	})
}

func DetermineSeveritySince(
	ctx context.Context,
	querier sql.Querier,
	imageName, pkg, cveID string,
	lastSeverity int32,
) (*time.Time, error) {

	earliest, err := querier.GetEarliestSeveritySinceForVulnerability(ctx, sql.GetEarliestSeveritySinceForVulnerabilityParams{
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
