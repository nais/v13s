package manager

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const KindUpsertImage = "upsert_image"

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

type UpsertImageWorker struct {
	db  sql.Querier
	log logrus.FieldLogger
	river.WorkerDefaults[UpsertImageJob]
}

func (u *UpsertImageWorker) Work(ctx context.Context, job *river.Job[UpsertImageJob]) error {
	data := job.Args.Data
	u.log.Infof("upserting vulnerabilities for %s:%s", data.ImageName, data.ImageTag)

	if err := u.upsertBatch(ctx, data); err != nil {
		return err
	}

	recordOutput(ctx, JobStatusImageSynced)
	return nil
}

func (u *UpsertImageWorker) upsertBatch(ctx context.Context, data *ImageVulnerabilityData) error {
	if data == nil {
		return nil
	}
	countError := 0
	errs := make([]error, 0)

	imageStates := make([]sql.BatchUpdateImageStateParams, 0)
	cves := make([]sql.BatchUpsertCveParams, 0)
	vulns := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	summaries := make([]sql.BatchUpsertVulnerabilitySummaryParams, 0)

	cves = append(cves, data.ToCveSqlParams()...)
	v, err := ToVulnerabilitySqlParams(ctx, u.db, data)
	if err != nil {
		countError++
		errs = append(errs, err)
	}
	vulns = append(vulns, v...)
	summaries = append(summaries, data.ToVulnerabilitySummarySqlParams())
	imageStates = append(imageStates, sql.BatchUpdateImageStateParams{
		State: sql.ImageStateUpdated,
		Name:  data.ImageName,
		Tag:   data.ImageTag,
	})

	metrics.SetWorkloadMetrics(data.Workloads, data.Summary)

	sortCveParams(cves)
	sortVulnerabilityParams(vulns)

	start := time.Now()
	var batchErr error
	u.db.BatchUpsertCve(ctx, cves).Exec(func(i int, err error) {
		if err != nil {
			u.log.WithError(err).Debug("failed to batch upsert cves")
			batchErr = err
			countError++
			errs = append(errs, err)
		}
	})
	upserted := len(cves) - countError
	u.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   upserted,
		"num_errors": countError,
	}).Infof("upserted batch of cves")

	start = time.Now()
	countError = 0
	u.db.BatchUpsertVulnerabilities(ctx, vulns).Exec(func(i int, err error) {
		if err != nil {
			u.log.WithError(err).Debug("failed to batch upsert vulnerabilities")
			batchErr = err
			countError++
			errs = append(errs, err)
		}
	})
	upserted = len(vulns) - countError
	u.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   upserted,
		"num_errors": countError,
	}).Infof("upserted batch of vulnerabilities")

	start = time.Now()
	countError = 0
	u.db.BatchUpsertVulnerabilitySummary(ctx, summaries).Exec(func(i int, err error) {
		if err != nil {
			u.log.WithError(err).Debug("failed to batch upsert vulnerability summary")
			batchErr = err
			countError++
			errs = append(errs, err)
		}
	})
	upserted = len(summaries) - countError
	u.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   upserted,
		"num_errors": countError,
	}).Infof("upserted batch of summaries")

	if len(errs) == 0 {
		start = time.Now()
		u.db.BatchUpdateImageState(ctx, imageStates).Exec(func(i int, err error) {
			if err != nil {
				u.log.WithError(err).Debug("failed to batch update image state")
				batchErr = err
				countError++
				errs = append(errs, err)
			}
		})
		u.log.WithError(batchErr).WithFields(logrus.Fields{
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
