//go:build integration_test

package policy_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/database/typeext"
	"github.com/nais/v13s/internal/policy"
	"github.com/nais/v13s/internal/test"
	"github.com/stretchr/testify/require"
)

func TestBulkUpdateCvePriorities_SkipsStaleWriteAfterConcurrentChange(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	db := sql.New(pool)

	const cveID = "CVE-RACE-TEST"
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{{CveID: cveID, Severity: 2, Refs: typeext.MapStringString{}}}).Exec(func(i int, err error) {
		require.NoError(t, err)
	})

	// This is what a Reprioritizer reads before computing a priority.
	rows, err := db.GetCvesForPriorityRecomputeByIDs(ctx, []string{cveID})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	staleRead := rows[0]

	// A concurrent writer lands after that read: a KEV sync flags this CVE,
	// which also bumps updated_at.
	_, err = db.BulkUpdateKevData(ctx, sql.BulkUpdateKevDataParams{
		CveIds:             []string{cveID},
		KnownRansomwareUse: []bool{false},
	})
	require.NoError(t, err)

	// Writing a priority computed from the now-stale read must be a no-op:
	// updated_at no longer matches what was read.
	updated, err := db.BulkUpdateCvePriorities(ctx, sql.BulkUpdateCvePrioritiesParams{
		CveIds:             []string{cveID},
		Priorities:         []int32{policy.PriorityMonitor},
		ExpectedUpdatedAts: []pgtype.Timestamptz{staleRead.UpdatedAt},
	})
	require.NoError(t, err)
	require.EqualValues(t, 0, updated, "a write computed from a stale read must be skipped")

	cve, err := db.GetCve(ctx, cveID)
	require.NoError(t, err)
	require.Nil(t, cve.Priority, "priority must be untouched by the skipped write")

	// A fresh read-then-write, as Reprioritizer actually does it, still lands.
	freshRows, err := db.GetCvesForPriorityRecomputeByIDs(ctx, []string{cveID})
	require.NoError(t, err)
	require.Len(t, freshRows, 1)

	updated, err = db.BulkUpdateCvePriorities(ctx, sql.BulkUpdateCvePrioritiesParams{
		CveIds:             []string{cveID},
		Priorities:         []int32{policy.PriorityHigh},
		ExpectedUpdatedAts: []pgtype.Timestamptz{freshRows[0].UpdatedAt},
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, updated, "a write computed from a fresh read must land")

	cve, err = db.GetCve(ctx, cveID)
	require.NoError(t, err)
	require.NotNil(t, cve.Priority)
	require.EqualValues(t, policy.PriorityHigh, *cve.Priority)
}
