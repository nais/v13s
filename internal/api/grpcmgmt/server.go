package grpcmgmt

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/internal/dependencytrack/client"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	log "github.com/sirupsen/logrus"
	"time"
)

var _ management.ManagementServer = (*Server)(nil)

type Server struct {
	management.UnimplementedManagementServer
	client dependencytrack.Client
	db     sql.Querier
}

func NewServer(db sql.Querier, client dependencytrack.Client) *Server {
	return &Server{
		db:     db,
		client: client,
	}
}

// TODO: consider doing some of the updates async with go routines and return a response immediately
func (s *Server) RegisterWorkload(ctx context.Context, request *management.RegisterWorkloadRequest) (*management.RegisterWorkloadResponse, error) {
	metadata := map[string]string{}
	if request.Metadata != nil {
		metadata = request.Metadata.Labels
	}

	_, err := s.db.GetImage(ctx, sql.GetImageParams{
		Name: request.ImageName,
		Tag:  request.ImageTag,
	})

	if errors.Is(err, pgx.ErrNoRows) {
		_, err = s.db.CreateImage(ctx, sql.CreateImageParams{
			Name:     request.ImageName,
			Tag:      request.ImageTag,
			Metadata: metadata,
		})

		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	w := sql.UpsertWorkloadParams{
		Name:         request.Workload,
		WorkloadType: request.WorkloadType,
		Namespace:    request.Namespace,
		Cluster:      request.Cluster,
		ImageName:    request.ImageName,
		ImageTag:     request.ImageTag,
	}

	err = s.db.UpsertWorkload(ctx, w)
	if err != nil {
		return nil, err
	}

	p, err := s.client.GetProject(ctx, request.ImageName, request.ImageTag)
	if err != nil {
		return nil, err
	}

	response := &management.RegisterWorkloadResponse{}
	if p == nil || p.Metrics == nil {
		return response, nil
	}

	// TODO: move this to a separate method and run async as metrics often is null for new workloads
	summary := sql.UpsertVulnerabilitySummaryParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
		Critical:  p.Metrics.Critical,
		High:      p.Metrics.High,
		Medium:    p.Metrics.Medium,
		Low:       p.Metrics.Low,
	}

	if p.Metrics.Unassigned != nil {
		summary.Unassigned = *p.Metrics.Unassigned
	}

	if p.Metrics.InheritedRiskScore != nil {
		summary.RiskScore = int32(*p.Metrics.InheritedRiskScore)
	}

	err = s.db.UpsertVulnerabilitySummary(ctx, summary)
	if err != nil {
		return nil, err
	}

	_, err = s.UpdateVulnerabilities(ctx, *p)
	if err != nil {
		return nil, err
	}

	return response, err
}

// TODO: use transactions to ensure consistency
func (s *Server) UpdateVulnerabilities(ctx context.Context, project client.Project) (any, error) {
	findings, err := s.client.GetFindings(ctx, project.Uuid, true)
	if err != nil {
		return nil, err
	}
	cweParams := make([]sql.BatchUpsertCweParams, 0)
	vulnParams := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	for _, f := range findings {
		v, cwe, err := s.parseFinding(*project.Name, *project.Version, f)
		if err != nil {
			return nil, err
		}
		cweParams = append(cweParams, sql.BatchUpsertCweParams{
			CweID:    cwe.CweID,
			CweTitle: cwe.CweTitle,
			CweDesc:  cwe.CweDesc,
			CweLink:  cwe.CweLink,
			Severity: cwe.Severity,
		})
		vulnParams = append(vulnParams, sql.BatchUpsertVulnerabilitiesParams{
			ImageName: v.ImageName,
			ImageTag:  v.ImageTag,
			Package:   v.Package,
			CweID:     v.CweID,
		})
	}

	// TODO: how to handle errors here?
	_, errors := s.upsertBatchCwe(ctx, cweParams)
	if errors > 0 {
		return nil, fmt.Errorf("error upserting CWEs, num errors: %d", errors)
	}

	_, errors = s.upsertBatchVulnerabilities(ctx, vulnParams)
	if errors > 0 {
		return nil, fmt.Errorf("error upserting CWEs, num errors: %d", errors)
	}

	return nil, nil
}

func (s *Server) upsertBatchVulnerabilities(ctx context.Context, batch []sql.BatchUpsertVulnerabilitiesParams) (upserted, errors int) {
	if len(batch) == 0 {
		return
	}

	start := time.Now()
	var batchErr error

	s.db.BatchUpsertVulnerabilities(ctx, batch).Exec(func(i int, err error) {
		if err != nil {
			batchErr = err
			errors++
		}
	})

	upserted += len(batch) - errors
	log.WithError(batchErr).WithFields(log.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": errors,
	}).Infof("upserted batch")
	return
}

func (s *Server) upsertBatchCwe(ctx context.Context, batch []sql.BatchUpsertCweParams) (upserted, errors int) {
	if len(batch) == 0 {
		return
	}

	start := time.Now()
	var batchErr error

	s.db.BatchUpsertCwe(ctx, batch).Exec(func(i int, err error) {
		if err != nil {
			batchErr = err
			errors++
		}
	})

	upserted += len(batch) - errors
	log.WithError(batchErr).WithFields(log.Fields{
		"duration":   time.Since(start),
		"num_rows":   upserted,
		"num_errors": errors,
	}).Infof("upserted batch")
	return
}

func runIfNoRows(err error, f func() error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		err = f()
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}
