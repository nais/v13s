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

func TestKevSourceEntries(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	const cveID = "CVE-2021-44228"
	const otherCveID = "CVE-2024-0001"
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{
		{CveID: cveID, CveTitle: cveID, Refs: map[string]string{}},
		{CveID: otherCveID, CveTitle: otherCveID, Refs: map[string]string{}},
	}).Exec(func(_ int, err error) {
		require.NoError(t, err)
	})
	_, err := pool.Exec(ctx, `DELETE FROM cve_kev_source`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE cve SET has_kev_entry = FALSE, known_ransomware_use = FALSE`)
	require.NoError(t, err)

	sync := func(cveID, source string, ransomware bool) *sql.Cve {
		t.Helper()
		_, err := db.UpsertKevSourceEntries(ctx, sql.UpsertKevSourceEntriesParams{
			CveIds:             []string{cveID},
			Sources:            []string{source},
			KnownRansomwareUse: []bool{ransomware},
		})
		require.NoError(t, err)
		_, err = db.RefreshCveKevFlags(ctx)
		require.NoError(t, err)
		cve, err := db.GetCve(ctx, cveID)
		require.NoError(t, err)
		return cve
	}

	cve := sync(cveID, "cisa", true)
	assert.True(t, cve.HasKevEntry)
	assert.True(t, cve.KnownRansomwareUse)

	cve = sync(cveID, "enisa", false)
	assert.True(t, cve.KnownRansomwareUse, "another source saying no ransomware must not clear CISA's claim")

	cve = sync(cveID, "cisa", false)
	assert.False(t, cve.KnownRansomwareUse, "CISA withdrawing its claim clears the flag without ENISA being fetched")

	sync(otherCveID, "cisa", false)
	cve, err = db.GetCve(ctx, cveID)
	require.NoError(t, err)
	assert.True(t, cve.HasKevEntry, "a CVE missing from the fetched data keeps its KEV entry")

	_, err = db.UpsertKevSourceEntries(ctx, sql.UpsertKevSourceEntriesParams{
		CveIds:             []string{"CVE-1999-9999"},
		Sources:            []string{"cisa"},
		KnownRansomwareUse: []bool{true},
	})
	require.NoError(t, err, "KEV CVEs not in the cve table are skipped")

	_, err = pool.Exec(ctx, `DELETE FROM cve_kev_source WHERE cve_id = $1`, cveID)
	require.NoError(t, err)
	_, err = db.RefreshCveKevFlags(ctx)
	require.NoError(t, err)
	cve, err = db.GetCve(ctx, cveID)
	require.NoError(t, err)
	assert.False(t, cve.HasKevEntry, "deleting a CVE's source rows removes its KEV entry")
}
