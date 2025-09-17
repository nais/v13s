package manager

import (
	"context"
	"errors"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const KindFetchImage = "fetch_image"

type FetchImageJob struct {
	ImageName string
	ImageTag  string
}

func (FetchImageJob) Kind() string { return KindFetchImage }

func (FetchImageJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindFetchImage,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 2 * time.Minute,
		},
		MaxAttempts: 3,
	}
}

type FetchImageWorker struct {
	db        sql.Querier
	source    sources.Source
	log       logrus.FieldLogger
	jobClient job.Client
	river.WorkerDefaults[FetchImageJob]
}

func (f *FetchImageWorker) Work(ctx context.Context, job *river.Job[FetchImageJob]) error {
	img := job.Args
	f.log.Debugf("fetching vulnerabilities for %s:%s", img.ImageName, img.ImageTag)

	data, err := f.fetchVulnerabilityData(ctx, img.ImageName, img.ImageTag, f.source)
	if err != nil {
		f.log.WithError(err).Error("fetch failed")
		if errors.Is(err, sources.ErrNoProject) {
			_ = f.jobClient.AddJob(ctx, RemoveFromSourceJob{
				ImageName: img.ImageName,
				ImageTag:  img.ImageTag,
			})
		}
		return err
	}

	recordOutput(ctx, JobStatusImageMetadataFetched)
	return f.jobClient.AddJob(ctx, UpsertImageJob{Data: data})
}

func (f *FetchImageWorker) fetchVulnerabilityData(ctx context.Context, imageName string, imageTag string, source sources.Source) (*ImageVulnerabilityData, error) {
	vulnerabilities, err := f.source.GetVulnerabilities(ctx, imageName, imageTag, true)
	if err != nil {
		return nil, err
	}
	f.log.Debugf("Got %d vulnerabilities", len(vulnerabilities))

	// sync suppressed vulnerabilities
	suppressedVulns, err := f.db.ListSuppressedVulnerabilitiesForImage(ctx, imageName)
	if err != nil {
		return nil, err
	}

	f.log.Debugf("Got %d suppressed vulnerabilities", len(suppressedVulns))
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

	err = f.source.MaintainSuppressedVulnerabilities(ctx, filteredVulnerabilities)
	if err != nil {
		return nil, err
	}

	summary, err := f.source.GetVulnerabilitySummary(ctx, imageName, imageTag)
	if err != nil {
		return nil, err
	}

	workloads, err := f.db.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
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
