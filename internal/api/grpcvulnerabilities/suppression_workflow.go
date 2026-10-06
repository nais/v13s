package grpcvulnerabilities

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type suppressionWorkflow struct {
	querier                sql.Querier
	resolveCanonicalCveIDs func(ctx context.Context, ids []string) ([]string, error)
	now                    func() time.Time
}

func newSuppressionWorkflow(querier sql.Querier, resolver func(ctx context.Context, ids []string) ([]string, error)) suppressionWorkflow {
	return suppressionWorkflow{
		querier:                querier,
		resolveCanonicalCveIDs: resolver,
		now:                    time.Now,
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
			return nil, status.Errorf(codes.NotFound, "vulnerability not found")
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
		return nil, fmt.Errorf("update image state: %w", err)
	}

	return &suppressOneResult{
		cveID:      vuln.CveID,
		suppressed: in.suppress,
	}, nil
}

func (w suppressionWorkflow) resolveToCanonicalAndAliases(ctx context.Context, cveID string) ([]string, error) {
	canonicalCveIDs, err := w.resolveCanonicalCveIDs(ctx, []string{cveID})
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
