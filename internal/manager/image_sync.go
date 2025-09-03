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
	Workloads       []Workload
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

	if err := s.jobClient.AddJob(ctx, &SyncWorkloadVulnerabilitiesJob{
		ImageName: img.ImageName,
		ImageTag:  img.ImageTag,
	}); err != nil {
		s.log.WithError(err).Errorf("failed to enqueue sync workload job for %s:%s", img.ImageName, img.ImageTag)
		// don't return error image job considered done
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
	ws := make([]Workload, 0, len(workloads))
	for _, w := range workloads {
		ws = append(ws, Workload{
			ID:        w.ID,
			Cluster:   w.Cluster,
			Namespace: w.Namespace,
			Name:      w.Name,
			Type:      w.WorkloadType,
		})
	}

	return &ImageVulnerabilityData{
		ImageName:       imageName,
		ImageTag:        imageTag,
		Source:          source.Name(),
		Vulnerabilities: vulnerabilities,
		Summary:         summary,
		Workloads:       ws,
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
		vulns = append(vulns, s.ToVulnerabilitySqlParams(ctx, i)...)
		summaries = append(summaries, i.ToVulnerabilitySummarySqlParams())
		imageStates = append(imageStates, sql.BatchUpdateImageStateParams{
			State: sql.ImageStateUpdated,
			Name:  i.ImageName,
			Tag:   i.ImageTag,
		})

		for _, w := range i.Workloads {
			metrics.WorkloadRiskScore.WithLabelValues(w.Cluster, w.Namespace, w.Name, w.Type).Set(float64(i.Summary.RiskScore))
			metrics.WorkloadCriticalCount.WithLabelValues(w.Cluster, w.Namespace, w.Name, w.Type).Set(float64(i.Summary.Critical))
		}
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

func (s *SyncImageWorker) ToVulnerabilitySqlParams(ctx context.Context, i *ImageVulnerabilityData) []sql.BatchUpsertVulnerabilitiesParams {
	params := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	for _, v := range i.Vulnerabilities {
		severity := v.Cve.Severity.ToInt32()
		becameCriticalAt, err := s.DetermineBecameCriticalAt(ctx, i.ImageName, v.Package, v.Cve.Id, severity)
		if err != nil {
			s.log.Errorf("determine becameCriticalAt: %v", err)
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

		if becameCriticalAt != nil {
			batch.BecameCriticalAt = pgtype.Timestamptz{
				Time:  *becameCriticalAt,
				Valid: true,
			}
		}
		params = append(params, batch)
	}
	return params
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

func (s *SyncImageWorker) DetermineBecameCriticalAt(ctx context.Context, imageName, pkg, cveID string, lastSeverity int32) (*time.Time, error) {
	if lastSeverity != 0 {
		// Not critical → no timestamp
		return nil, nil
	}

	// Query DB for earliest known critical timestamp for this vuln across all tags
	earliest, err := s.db.GetEarliestCriticalAtForVulnerability(ctx, sql.GetEarliestCriticalAtForVulnerabilityParams{
		ImageName: imageName,
		Package:   pkg,
		CveID:     cveID,
	})
	if err != nil {
		return nil, err
	}

	if earliest.Valid {
		s.log.Debugf("Vulnerability %s in package %s for image %s became critical at %s", cveID, pkg, imageName, earliest.Time)
		return &earliest.Time, nil
	}

	now := time.Now().UTC()
	return &now, nil
}
