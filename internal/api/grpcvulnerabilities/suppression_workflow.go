package grpcvulnerabilities

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type suppressionWorkflow struct {
	querier               sql.Querier
	resolveCanonicalCveID func(ctx context.Context, ids []string) ([]string, error)
	now                   func() time.Time
}

func newSuppressionWorkflow(querier sql.Querier, resolver func(ctx context.Context, ids []string) ([]string, error)) suppressionWorkflow {
	return suppressionWorkflow{
		querier:               querier,
		resolveCanonicalCveID: resolver,
		now:                   time.Now,
	}
}

type suppressOneInput struct {
	id           pgtype.UUID
	suppressedBy string
	suppress     bool
	reason       sql.VulnerabilitySuppressReason
	reasonText   string
}

type suppressOneResult struct {
	cveID      string
	suppressed bool
}

func (w suppressionWorkflow) SuppressOne(ctx context.Context, in suppressOneInput) (*suppressOneResult, error) {
	vuln, err := w.querier.GetVulnerabilityById(ctx, in.id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("vulnerability not found")
		}
		return nil, fmt.Errorf("get suppressed vulnerability: %w", err)
	}

	cveIDs, err := w.resolveToCanonicalAndAliases(ctx, vuln.CveID)
	if err != nil {
		return nil, err
	}

	suppressParams := sql.SuppressVulnerabilityParams{
		ImageName:    vuln.ImageName,
		Package:      vuln.Package,
		SuppressedBy: in.suppressedBy,
		Suppressed:   in.suppress,
		Reason:       in.reason,
		ReasonText:   in.reasonText,
	}

	var suppressErrs []string
	for _, cveID := range cveIDs {
		suppressParams.CveID = cveID
		if supErr := w.querier.SuppressVulnerability(ctx, suppressParams); supErr != nil {
			suppressErrs = append(suppressErrs, fmt.Sprintf("%s: %v", cveID, supErr))
		}
	}
	if len(suppressErrs) > 0 {
		return nil, fmt.Errorf("failed to suppress %d/%d CVE IDs for %s/%s: %s", len(suppressErrs), len(cveIDs), vuln.ImageName, vuln.Package, strings.Join(suppressErrs, "; "))
	}

	if err := w.querier.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
		ImageName: vuln.ImageName,
		ImageTag:  vuln.ImageTag,
	}); err != nil {
		return nil, fmt.Errorf("recalculate vulnerability summary: %w", err)
	}

	_, err = w.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
		State: sql.ImageStateResync,
		Name:  vuln.ImageName,
		Tag:   vuln.ImageTag,
		ReadyForResyncAt: pgtype.Timestamptz{
			Time:  w.now(),
			Valid: true,
		},
	})
	if err != nil {
		return nil, err
	}

	return &suppressOneResult{
		cveID:      vuln.CveID,
		suppressed: in.suppress,
	}, nil
}

type suppressManyInput struct {
	requestCveID string
	suppressedBy string
	suppress     bool
	reason       sql.VulnerabilitySuppressReason
	reasonText   string
	workloads    []*vulnerabilities.SuppressVulnerabilitiesWorkload
}

type suppressManyResult struct {
	cveID         string
	workloadCount int32
	imageCount    int32
	errors        []string
	workloads     []*vulnerabilities.SuppressVulnerabilitiesWorkload
}

func (w suppressionWorkflow) SuppressManySameNamespace(ctx context.Context, in suppressManyInput) (*suppressManyResult, error) {
	cveIDs, err := w.resolveToCanonicalAndAliases(ctx, in.requestCveID)
	if err != nil {
		return nil, err
	}
	canonicalCveID := cveIDs[0]

	clusters := make([]string, 0, len(in.workloads))
	namespaces := make([]string, 0, len(in.workloads))
	names := make([]string, 0, len(in.workloads))
	workloadTypes := make([]string, 0, len(in.workloads))
	for _, workload := range in.workloads {
		clusters = append(clusters, workload.GetCluster())
		namespaces = append(namespaces, workload.GetNamespace())
		names = append(names, workload.GetName())
		workloadTypes = append(workloadTypes, workload.GetWorkloadType())
	}

	images, err := w.querier.GetImagesForCveAndWorkloads(ctx, sql.GetImagesForCveAndWorkloadsParams{
		CveID:         canonicalCveID,
		Clusters:      clusters,
		Namespaces:    namespaces,
		Names:         names,
		WorkloadTypes: workloadTypes,
	})
	if err != nil {
		return nil, fmt.Errorf("get images for cve and workloads: %w", err)
	}
	if len(images) == 0 {
		return nil, status.Errorf(codes.NotFound, "no matching images found for cve %s and provided workloads", in.requestCveID)
	}

	type imageKey struct {
		name string
		tag  string
	}

	seenImages := make(map[imageKey]struct{})
	seenWorkloads := make(map[string]*vulnerabilities.SuppressVulnerabilitiesWorkload)
	var suppressErrs []string

	suppressParams := sql.SuppressVulnerabilityParams{
		SuppressedBy: in.suppressedBy,
		Suppressed:   in.suppress,
		Reason:       in.reason,
		ReasonText:   in.reasonText,
	}

	for _, img := range images {
		suppressParams.ImageName = img.ImageName
		suppressParams.Package = img.Package
		for _, cveID := range cveIDs {
			suppressParams.CveID = cveID
			if supErr := w.querier.SuppressVulnerability(ctx, suppressParams); supErr != nil {
				suppressErrs = append(suppressErrs, fmt.Sprintf("%s/%s/%s: %v", img.ImageName, img.Package, cveID, supErr))
			}
		}
		seenImages[imageKey{name: img.ImageName, tag: img.ImageTag}] = struct{}{}
		key := fmt.Sprintf("%s/%s/%s/%s", img.WorkloadCluster, img.WorkloadNamespace, img.WorkloadName, img.WorkloadType)
		seenWorkloads[key] = &vulnerabilities.SuppressVulnerabilitiesWorkload{
			Cluster:      img.WorkloadCluster,
			Namespace:    img.WorkloadNamespace,
			Name:         img.WorkloadName,
			WorkloadType: img.WorkloadType,
			ImageName:    img.ImageName,
			ImageTag:     img.ImageTag,
		}
	}

	for key := range seenImages {
		if recErr := w.querier.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
			ImageName: key.name,
			ImageTag:  key.tag,
		}); recErr != nil {
			suppressErrs = append(suppressErrs, fmt.Sprintf("recalculate summary %s:%s: %v", key.name, key.tag, recErr))
		}
		if _, updateErr := w.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
			State: sql.ImageStateResync,
			Name:  key.name,
			Tag:   key.tag,
			ReadyForResyncAt: pgtype.Timestamptz{
				Time:  w.now(),
				Valid: true,
			},
		}); updateErr != nil {
			suppressErrs = append(suppressErrs, fmt.Sprintf("update image state %s:%s: %v", key.name, key.tag, updateErr))
		}
	}

	workloadCount := len(seenWorkloads)
	imageCount := len(seenImages)
	if workloadCount > math.MaxInt32 || imageCount > math.MaxInt32 {
		return nil, fmt.Errorf("result count exceeds int32 range")
	}

	suppressedWorkloads := make([]*vulnerabilities.SuppressVulnerabilitiesWorkload, 0, workloadCount)
	for _, workload := range seenWorkloads {
		suppressedWorkloads = append(suppressedWorkloads, workload)
	}

	return &suppressManyResult{
		cveID:         in.requestCveID,
		workloadCount: int32(workloadCount), //#nosec G115
		imageCount:    int32(imageCount),    //#nosec G115
		errors:        suppressErrs,
		workloads:     suppressedWorkloads,
	}, nil
}

func (w suppressionWorkflow) resolveToCanonicalAndAliases(ctx context.Context, cveID string) ([]string, error) {
	canonicalCveIDs, err := w.resolveCanonicalCveID(ctx, []string{cveID})
	if err != nil {
		return nil, err
	}
	canonical := canonicalCveIDs[0]

	all := []string{canonical}
	aliases, err := w.querier.GetAliasesByCanonicalCveId(ctx, canonical)
	if err != nil {
		return nil, fmt.Errorf("get aliases for cve: %w", err)
	}
	if len(aliases) > 0 {
		all = append(all, aliases...)
	}
	return all, nil
}
