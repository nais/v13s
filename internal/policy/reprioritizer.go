package policy

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
)

// Reprioritizer recomputes cve.priority via a PriorityEvaluator and writes
// back only the rows that changed, in one batched read and one batched write.
type Reprioritizer struct {
	querier   sql.Querier
	evaluator *PriorityEvaluator
}

func NewReprioritizer(querier sql.Querier, evaluator *PriorityEvaluator) *Reprioritizer {
	return &Reprioritizer{querier: querier, evaluator: evaluator}
}

type cveForPriority struct {
	cveID              string
	severity           int32
	epssScore          *float64
	epssPercentile     *float64
	hasKevEntry        bool
	knownRansomwareUse bool
	priority           *int32
	updatedAt          pgtype.Timestamptz
}

// ReprioritizeAll recomputes priority for every CVE in the table.
func (r *Reprioritizer) ReprioritizeAll(ctx context.Context) (int64, error) {
	rows, err := r.querier.GetCvesForPriorityRecompute(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetching cves for priority recompute: %w", err)
	}
	cves := make([]cveForPriority, len(rows))
	for i, row := range rows {
		cves[i] = cveForPriority{
			row.CveID, row.Severity, row.EpssScore, row.EpssPercentile,
			row.HasKevEntry, row.KnownRansomwareUse, row.Priority, row.UpdatedAt,
		}
	}
	return r.apply(ctx, cves)
}

// ReprioritizeCves recomputes priority for the given CVE IDs only.
func (r *Reprioritizer) ReprioritizeCves(ctx context.Context, cveIDs []string) (int64, error) {
	if len(cveIDs) == 0 {
		return 0, nil
	}
	rows, err := r.querier.GetCvesForPriorityRecomputeByIDs(ctx, cveIDs)
	if err != nil {
		return 0, fmt.Errorf("fetching cves for priority recompute: %w", err)
	}
	cves := make([]cveForPriority, len(rows))
	for i, row := range rows {
		cves[i] = cveForPriority{
			row.CveID, row.Severity, row.EpssScore, row.EpssPercentile,
			row.HasKevEntry, row.KnownRansomwareUse, row.Priority, row.UpdatedAt,
		}
	}
	return r.apply(ctx, cves)
}

func (r *Reprioritizer) apply(ctx context.Context, cves []cveForPriority) (int64, error) {
	var cveIDs []string
	var priorities []int32
	var expectedUpdatedAts []pgtype.Timestamptz

	for _, c := range cves {
		input := PriorityInput{Severity: c.severity, HasKevEntry: c.hasKevEntry, KnownRansomwareUse: c.knownRansomwareUse}
		if c.epssScore != nil {
			input.EpssScore = *c.epssScore
		}
		if c.epssPercentile != nil {
			input.EpssPercentile = *c.epssPercentile
		}

		tier, err := r.evaluator.Evaluate(input)
		if err != nil {
			return 0, fmt.Errorf("evaluating priority for cve %s: %w", c.cveID, err)
		}
		if c.priority != nil && *c.priority == tier {
			continue
		}

		cveIDs = append(cveIDs, c.cveID)
		priorities = append(priorities, tier)
		expectedUpdatedAts = append(expectedUpdatedAts, c.updatedAt)
	}

	if len(cveIDs) == 0 {
		return 0, nil
	}

	updated, err := r.querier.BulkUpdateCvePriorities(ctx, sql.BulkUpdateCvePrioritiesParams{
		CveIds:             cveIDs,
		Priorities:         priorities,
		ExpectedUpdatedAts: expectedUpdatedAts,
	})
	if err != nil {
		return 0, fmt.Errorf("writing cve priorities: %w", err)
	}
	return updated, nil
}
