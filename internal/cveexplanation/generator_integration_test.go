//go:build integration_test

package cveexplanation

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/stretchr/testify/require"
)

func TestCveExplanationIntegration(t *testing.T) {
	ctx := t.Context()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	g, _ := newTestGenerator(4)
	g.pool, g.store = pool, db

	for n, fixture := range []struct {
		workloadState string
		imageState    string
		kev           bool
	}{
		{"updated", "updated", true},
		{"failed", "updated", true},
		{"updated", "updated", false},
		{"updated", "unused", true},
	} {
		id := fmt.Sprintf("CVE-2024-%04d", 1000+n)
		image := fmt.Sprintf("explanation-image-%d", n)
		_, err := pool.Exec(ctx, `INSERT INTO cve(cve_id, cve_title, cve_desc, cve_link, severity, refs, has_kev_entry)
			VALUES ($1, $1, 'description', '', 0, '{}', $2)`, id, fixture.kev)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `INSERT INTO images(name, tag, state) VALUES ($1, 'v1', $2)`, image, fixture.imageState)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `INSERT INTO workloads(name, workload_type, namespace, cluster, image_name, image_tag, state)
			VALUES ($1, 'deployment', 'test', 'test', $1, 'v1', $2)`, image, fixture.workloadState)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `INSERT INTO vulnerabilities(image_name, image_tag, package, cve_id, source, latest_version)
			VALUES ($1, 'v1', 'pkg:maven/public/example@1', $2, 'test', '1')`, image, id)
		require.NoError(t, err)
	}
	const cveID = "CVE-2024-1000"
	_, err := pool.Exec(ctx, `INSERT INTO cve(cve_id, cve_title, cve_desc, cve_link, severity, refs)
		VALUES ('GHSA-test-alias', 'alias', '', '', 0, '{}')`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO cve_alias(alias, canonical_cve_id) VALUES ('GHSA-test-alias', $1)`, cveID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO vulnerabilities(image_name, image_tag, package, cve_id, source, latest_version)
		VALUES ('explanation-image-0', 'v1', 'pkg:maven/public/other@1', 'GHSA-test-alias', 'test', '1')`)
	require.NoError(t, err)

	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	locked, err := sql.New(conn).TryAdvisoryLock(ctx, explanationLockKey)
	require.NoError(t, err)
	require.True(t, locked)
	require.NoError(t, g.Run(ctx))
	_, err = db.GetCveExplanation(ctx, sql.GetCveExplanationParams{CveID: cveID, PromptVersion: PromptVersion})
	require.ErrorIs(t, err, pgx.ErrNoRows)
	_, err = sql.New(conn).AdvisoryUnlock(ctx, explanationLockKey)
	require.NoError(t, err)
	conn.Release()

	var calls int
	g.client = clientFunc(func(context.Context, Input) (Explanation, error) {
		calls++
		return Explanation{Summary: "Forklaring", Action: "Følg advisoryen"}, nil
	})
	require.NoError(t, g.Run(ctx))
	require.Equal(t, 1, calls, "only the active public KEV CVE is generated, once across aliases/packages")
	result, err := db.GetCveExplanation(ctx, sql.GetCveExplanationParams{CveID: cveID, PromptVersion: PromptVersion})
	require.NoError(t, err)
	require.Equal(t, "Forklaring", *result.Summary)
	aliasResult, err := db.GetCveExplanation(ctx, sql.GetCveExplanationParams{CveID: "GHSA-test-alias", PromptVersion: PromptVersion})
	require.NoError(t, err)
	require.Equal(t, *result.Summary, *aliasResult.Summary)
	require.NoError(t, g.Run(ctx))
	require.Equal(t, 1, calls, "unchanged inputs do not regenerate")

	_, err = pool.Exec(ctx, `UPDATE cve_explanation SET prompt_version = 0 WHERE cve_id = $1`, cveID)
	require.NoError(t, err)
	require.NoError(t, g.Run(ctx))
	require.Equal(t, 2, calls, "prompt changes regenerate")

	original, err := g.catalog.Fetch(ctx)
	require.NoError(t, err)
	updated := original[cveID]
	updated.Description = "Corrected public description"
	original[cveID] = updated
	g.catalog = catalogFunc(func(context.Context) (map[string]Input, error) { return original, nil })
	require.NoError(t, g.Run(ctx))
	require.Equal(t, 3, calls, "source changes regenerate")

	staleSummary, staleAction, model := "Old explanation", "Old action", "gemini-test"
	rows, err := db.SaveCveExplanation(ctx, sql.SaveCveExplanationParams{
		CveID: cveID, PromptVersion: PromptVersion, InputHash: "obsolete",
		Summary: &staleSummary, Action: &staleAction, Model: &model,
	})
	require.NoError(t, err)
	require.Zero(t, rows, "a stale result cannot overwrite the current explanation")

	_, err = pool.Exec(ctx, `UPDATE cve_explanation SET prompt_version = 0 WHERE cve_id = $1`, cveID)
	require.NoError(t, err)
	g.client = clientFunc(func(context.Context, Input) (Explanation, error) { return Explanation{}, modelError{code: 400} })
	require.Error(t, g.Run(ctx))
	_, err = db.GetCveExplanation(ctx, sql.GetCveExplanationParams{CveID: cveID, PromptVersion: PromptVersion})
	require.ErrorIs(t, err, pgx.ErrNoRows, "an outdated explanation is hidden if regeneration fails")

	_, err = pool.Exec(ctx, `INSERT INTO cve(cve_id, cve_title, cve_desc, cve_link, severity, refs, has_kev_entry)
		VALUES ('CVE-2024-2000', 'new CVE', '', '', 0, '{}', TRUE)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO vulnerabilities(image_name, image_tag, package, cve_id, source, latest_version)
		VALUES ('explanation-image-0', 'v1', 'pkg:maven/public/new@1', 'CVE-2024-2000', 'test', '1')`)
	require.NoError(t, err)
	next := publicInput()
	next.CveID = "CVE-2024-2000"
	original[next.CveID] = next
	g.config.MaxPerRun = 1
	var selected string
	g.client = clientFunc(func(_ context.Context, input Input) (Explanation, error) {
		selected = input.CveID
		return Explanation{Summary: "Forklaring", Action: "Følg advisoryen"}, nil
	})
	require.NoError(t, g.Run(ctx))
	require.Equal(t, next.CveID, selected, "a failed CVE does not starve unattempted candidates")
}
