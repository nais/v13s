//go:build integration_test

package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/stretchr/testify/require"
)

func TestOsvFindingRowLimit(t *testing.T) {
	ctx := t.Context()
	pool := test.GetPool(context.Background(), t, true)
	db := sql.New(pool)
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag)
		SELECT 'osv-test', n::text FROM generate_series(1, 2003) n;
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs)
		VALUES ('CVE-OSV-TEST', '', '', '', 1, '{}');
		INSERT INTO vulnerabilities (image_name, image_tag, package, cve_id, source, latest_version)
		SELECT 'osv-test', n::text, 'pkg:npm/example@1.0.0', 'CVE-OSV-TEST', 'test', ''
		FROM generate_series(1, 2003) n`)
	require.NoError(t, err)

	update := sql.BulkUpdateFixVersionsParams{
		CveIds:      []string{"CVE-OSV-TEST"},
		Packages:    []string{"pkg:npm/example@1.0.0"},
		FixVersions: []string{"2.0.0"},
		FixStatuses: []string{"fix_available"},
	}
	clear := sql.BulkClearFixVersionsParams{
		CveIds:      update.CveIds,
		Packages:    update.Packages,
		FixStatuses: []string{"no_fix_available"},
	}
	for _, write := range []func() (int64, error){
		func() (int64, error) { return db.BulkUpdateFixVersions(ctx, update) },
		func() (int64, error) { return db.BulkClearFixVersions(ctx, clear) },
	} {
		for _, want := range []int64{1000, 1000, 3, 0} {
			n, err := write()
			require.NoError(t, err)
			require.Equal(t, want, n)
		}
	}
}

func TestOsvLocksFindingsInResyncOrder(t *testing.T) {
	pool := test.GetPool(context.Background(), t, true)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag) VALUES ('osv-test', '1');
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs)
		VALUES ('CVE-OSV-TEST', '', '', '', 1, '{}');
		INSERT INTO vulnerabilities (image_name, image_tag, package, cve_id, source, latest_version)
		VALUES ('osv-test', '1', 'b', 'CVE-OSV-TEST', 'test', ''),
		       ('osv-test', '1', 'a', 'CVE-OSV-TEST', 'test', '')`)
	require.NoError(t, err)

	for _, clear := range []bool{false, true} {
		t.Run(map[bool]string{false: "update", true: "clear"}[clear], func(t *testing.T) {
			resync, err := pool.Begin(ctx)
			require.NoError(t, err)
			defer resync.Rollback(context.Background())
			_, err = resync.Exec(ctx, "SET LOCAL lock_timeout = '500ms'")
			require.NoError(t, err)
			upsert := func(pkg string) error {
				batch := sql.New(resync).BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
					{ImageName: "osv-test", ImageTag: "1", Package: pkg, CveID: "CVE-OSV-TEST", Source: "test"},
				})
				var execErr error
				batch.Exec(func(_ int, err error) { execErr = err })
				closeErr := batch.Close()
				if execErr != nil {
					return execErr
				}
				return closeErr
			}
			require.NoError(t, upsert("a"))

			conn, err := pool.Acquire(ctx)
			require.NoError(t, err)
			defer conn.Release()
			workCtx, stop := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() {
				q := sql.New(conn)
				var writeErr error
				if clear {
					_, writeErr = q.BulkClearFixVersions(workCtx, sql.BulkClearFixVersionsParams{
						CveIds: []string{"CVE-OSV-TEST", "CVE-OSV-TEST"}, Packages: []string{"b", "a"},
						FixStatuses: []string{"no_fix_available", "no_fix_available"},
					})
				} else {
					_, writeErr = q.BulkUpdateFixVersions(workCtx, sql.BulkUpdateFixVersionsParams{
						CveIds: []string{"CVE-OSV-TEST", "CVE-OSV-TEST"}, Packages: []string{"b", "a"},
						FixVersions: []string{"2", "2"}, FixStatuses: []string{"fix_available", "fix_available"},
					})
				}
				done <- writeErr
			}()
			finished := false
			defer func() {
				stop()
				if !finished {
					<-done
				}
			}()

			require.Eventually(t, func() bool {
				var blocked bool
				err := pool.QueryRow(ctx, "SELECT cardinality(pg_blocking_pids($1)) > 0", int32(conn.Conn().PgConn().PID())).Scan(&blocked)
				require.NoError(t, err)
				return blocked
			}, 5*time.Second, 10*time.Millisecond)
			require.NoError(t, upsert("b"), "OSV must wait at a before locking b")
			require.NoError(t, resync.Commit(ctx))
			writeErr := <-done
			finished = true
			require.NoError(t, writeErr)
		})
	}
}
