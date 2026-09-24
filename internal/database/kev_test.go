//go:build integration_test

package database_test

import (
	"context"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBulkUpdateKevData(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	const cveID = "CVE-2021-44228"
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{{CveID: cveID, CveTitle: cveID, Refs: map[string]string{}}}).Exec(func(_ int, err error) {
		require.NoError(t, err)
	})

	update := func(ransomware bool, sources []string, complete bool) *sql.Cve {
		t.Helper()
		params := sql.BulkUpdateKevDataParams{
			CveIds:             []string{cveID},
			KnownRansomwareUse: []bool{ransomware},
			Complete:           complete,
		}
		for _, s := range sources {
			params.SourceCveIds = append(params.SourceCveIds, cveID)
			params.SourceNames = append(params.SourceNames, s)
		}
		_, err := db.BulkUpdateKevData(ctx, params)
		require.NoError(t, err)
		cve, err := db.GetCve(ctx, cveID)
		require.NoError(t, err)
		return cve
	}

	cve := update(true, []string{"cisa"}, true)
	assert.True(t, cve.HasKevEntry)
	assert.True(t, cve.KnownRansomwareUse)
	assert.Equal(t, []string{"cisa"}, cve.KevSources)

	cve = update(false, []string{"enisa"}, false)
	assert.True(t, cve.KnownRansomwareUse, "a partial run must not clear the ransomware flag")
	assert.Equal(t, []string{"cisa", "enisa"}, cve.KevSources, "a partial run only adds sources")

	cve = update(false, []string{"enisa"}, true)
	assert.False(t, cve.KnownRansomwareUse)
	assert.Equal(t, []string{"enisa"}, cve.KevSources)

	const otherCveID = "CVE-2024-0001"
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{{CveID: otherCveID, CveTitle: otherCveID, Refs: map[string]string{}}}).Exec(func(_ int, err error) {
		require.NoError(t, err)
	})
	listOther := func(complete bool) *sql.Cve {
		t.Helper()
		_, err := db.BulkUpdateKevData(ctx, sql.BulkUpdateKevDataParams{
			CveIds:             []string{otherCveID},
			KnownRansomwareUse: []bool{false},
			SourceCveIds:       []string{otherCveID},
			SourceNames:        []string{"cisa"},
			Complete:           complete,
		})
		require.NoError(t, err)
		cve, err := db.GetCve(ctx, cveID)
		require.NoError(t, err)
		return cve
	}

	cve = listOther(false)
	assert.True(t, cve.HasKevEntry, "a partial run must not clear CVEs missing from the fetched data")
	assert.Equal(t, []string{"enisa"}, cve.KevSources)

	cve = listOther(true)
	assert.False(t, cve.HasKevEntry, "a complete run clears CVEs no source lists any more")
	assert.Empty(t, cve.KevSources)
}
