//go:build integration_test

package database_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/sources/osv"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/internal/updater"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestChainguardCorrectionsAllowConcurrentImageUpdates(t *testing.T) {
	pool := test.GetPool(t.Context(), t, true)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag, state) VALUES ('image', 'v1', 'updated'), ('image', 'v2', 'updated');
		CREATE FUNCTION pause_first_image_update() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(9137, 1);
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER pause_first_image_update AFTER INSERT ON vulnerabilities
			FOR EACH ROW WHEN (NEW.image_tag = 'v1')
			EXECUTE FUNCTION pause_first_image_update();
	`)
	require.NoError(t, err)
	blocker, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer blocker.Release()
	_, err = blocker.Exec(ctx, "SELECT pg_advisory_lock(9137, 1)")
	require.NoError(t, err)
	var workers sync.WaitGroup
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = blocker.Exec(cleanupCtx, "SELECT pg_advisory_unlock(9137, 1)")
		cancel()
		workers.Wait()
	}()

	log, _ := logrustest.NewNullLogger()
	u := updater.NewUpdater(pool, nil, updater.ScheduleConfig{}, log.WithField("test", true), config.KevConfig{}, config.OsvConfig{})
	update := func(ctx context.Context, tag string) error {
		return u.BatchUpdateVulnerabilityData(ctx, []*updater.ImageVulnerabilityData{{
			ImageName: "image", ImageTag: tag, Source: "test",
			Vulnerabilities: []*sources.Vulnerability{{
				Package: "pkg:apk/chainguard/glibc-2.44@2.44-r11?arch=x86_64&distro=20230214",
				Cve: &sources.Cve{
					Id: "CGA-fjmw-f657-w678", Title: "test", Description: "test", Link: "test",
					Severity: sources.SeverityHigh, References: map[string]string{},
				},
			}},
		}})
	}
	firstDone := make(chan error, 1)
	workers.Go(func() { firstDone <- update(ctx, "v1") })
	require.Eventually(t, func() bool {
		var blocked bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted)
		`).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond, "first image update must pause before commit")

	secondCtx, secondCancel := context.WithTimeout(ctx, 5*time.Second)
	defer secondCancel()
	require.NoError(t, update(secondCtx, "v2"), "another image with the same advisory must update without waiting")
	var firstCount, secondCount int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE image_tag = 'v1'), COUNT(*) FILTER (WHERE image_tag = 'v2')
		FROM vulnerabilities WHERE image_name = 'image'
	`).Scan(&firstCount, &secondCount))
	require.Zero(t, firstCount)
	require.Equal(t, 1, secondCount)

	_, err = blocker.Exec(ctx, "SELECT pg_advisory_unlock(9137, 1)")
	require.NoError(t, err)
	require.NoError(t, <-firstDone)
}

func TestChainguardCorrectionClearingWithConcurrentImage(t *testing.T) {
	pool := test.GetPool(t.Context(), t, true)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	q := sql.New(pool)
	const (
		cga = "CGA-fjmw-f657-w678"
		pkg = "pkg:apk/chainguard/glibc-2.44@2.44-r11?arch=x86_64&distro=20230214"
	)
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag, state) VALUES ('image', 'v1', 'updated'), ('image', 'v2', 'updated');
		INSERT INTO workloads (name, workload_type, namespace, cluster, image_name, image_tag, state) VALUES
			('one', 'app', 'team', 'dev', 'image', 'v1', 'updated'),
			('two', 'app', 'team', 'dev', 'image', 'v2', 'updated');
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs)
			VALUES ('CGA-fjmw-f657-w678', 'test', 'test', 'test', 1, '{}');
		INSERT INTO vulnerabilities (image_name, image_tag, cve_id, package, source, latest_version)
			VALUES ('image', 'v1', 'CGA-fjmw-f657-w678',
				'pkg:apk/chainguard/glibc-2.44@2.44-r11?arch=x86_64&distro=20230214', 'test', '');
	`)
	require.NoError(t, err)
	require.NoError(t, q.SaveChainguardCorrection(ctx, sql.SaveChainguardCorrectionParams{
		CveID: cga, Package: pkg, FixStatus: sql.FixStatusInstalledVersionFixed,
		SourceUrl: "https://advisories.cgr.dev/chainguard/v3/osv/" + cga + ".json",
	}))
	require.NoError(t, q.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
		ImageName: "image", ImageTag: "v1",
	}))
	_, err = pool.Exec(ctx, `
		CREATE FUNCTION pause_correction_summary() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(9137, 1);
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER pause_correction_summary AFTER UPDATE ON vulnerability_summary
			FOR EACH ROW WHEN (NEW.image_name = 'image' AND NEW.image_tag = 'v1')
			EXECUTE FUNCTION pause_correction_summary();
	`)
	require.NoError(t, err)
	blocker, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer blocker.Release()
	_, err = blocker.Exec(ctx, "SELECT pg_advisory_lock(9137, 1)")
	require.NoError(t, err)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = blocker.Exec(cleanupCtx, "SELECT pg_advisory_unlock(9137, 1)")
	}()

	log, _ := logrustest.NewNullLogger()
	fetcher := osv.NewFetcherWithClient(osv.NewClientWithURL(""), pool, log.WithField("test", true)).WithChainguard(false)
	clearDone := make(chan error, 1)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	workers.Go(func() { clearDone <- fetcher.Sync(ctx) })
	require.Eventually(t, func() bool {
		var blocked bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted)
		`).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond, "correction clearing must pause after loading its affected images")

	u := updater.NewUpdater(pool, nil, updater.ScheduleConfig{}, log.WithField("test", true), config.KevConfig{}, config.OsvConfig{})
	updateDone := make(chan error, 1)
	workers.Go(func() {
		updateDone <- u.BatchUpdateVulnerabilityData(ctx, []*updater.ImageVulnerabilityData{{
			ImageName: "image", ImageTag: "v2", Source: "test",
			Vulnerabilities: []*sources.Vulnerability{{
				Package: pkg,
				Cve: &sources.Cve{
					Id: cga, Title: "test", Description: "test", Link: "test",
					Severity: sources.SeverityHigh, References: map[string]string{},
				},
			}},
		}})
	})
	var updateErr error
	updateFinished := false
	require.Eventually(t, func() bool {
		select {
		case updateErr = <-updateDone:
			updateFinished = true
			return true
		default:
		}
		var blocked bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objsubid = 1 AND NOT granted)
		`).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond, "image update must finish or wait for correction clearing")
	_, err = blocker.Exec(ctx, "SELECT pg_advisory_unlock(9137, 1)")
	require.NoError(t, err)
	require.NoError(t, <-clearDone)
	if !updateFinished {
		updateErr = <-updateDone
	}
	require.NoError(t, updateErr)

	detail, err := q.GetVulnerability(ctx, sql.GetVulnerabilityParams{
		ImageName: "image", ImageTag: "v2", CveID: cga, Package: pkg,
	})
	require.NoError(t, err)
	require.NotNil(t, detail.FixStatus)
	require.Equal(t, sql.FixStatusUnknown, *detail.FixStatus)
	findings, err := q.ListVulnerabilitiesForImage(ctx, sql.ListVulnerabilitiesForImageParams{
		ImageName: "image", ImageTag: "v2", Limit: 50,
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	var risk int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT risk_score FROM vulnerability_summary WHERE image_name = 'image' AND image_tag = 'v2'
	`).Scan(&risk))
	require.Equal(t, 5, risk)
}

func TestChainguardCorrectionWithConcurrentCountsRefresh(t *testing.T) {
	pool := test.GetPool(t.Context(), t, true)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	q := sql.New(pool)
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag, state) VALUES ('image', 'v1', 'updated');
		INSERT INTO workloads (name, workload_type, namespace, cluster, image_name, image_tag, state)
			VALUES ('one', 'app', 'team', 'dev', 'image', 'v1', 'updated');
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs)
			VALUES ('CGA-fjmw-f657-w678', 'test', 'test', 'test', 1, '{}');
		INSERT INTO vulnerabilities (image_name, image_tag, cve_id, package, source, latest_version)
			VALUES ('image', 'v1', 'CGA-fjmw-f657-w678', 'package', 'test', '');
	`)
	require.NoError(t, err)
	require.NoError(t, q.SaveChainguardCorrection(ctx, sql.SaveChainguardCorrectionParams{
		CveID: "CGA-fjmw-f657-w678", Package: "package", FixStatus: sql.FixStatusInstalledVersionFixed,
		SourceUrl: "https://advisories.cgr.dev/chainguard/v3/osv/CGA-fjmw-f657-w678.json",
	}))
	require.NoError(t, q.RefreshCveWorkloadCounts(ctx))
	refreshConn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer refreshConn.Release()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	var workers sync.WaitGroup
	defer func() {
		_ = tx.Rollback(context.Background())
		cancel()
		workers.Wait()
	}()
	txq := sql.New(tx)
	require.NoError(t, txq.LockChainguardCorrections(ctx))
	require.NoError(t, txq.ClearChainguardCorrections(ctx))
	require.NoError(t, txq.RefreshCveWorkloadCounts(ctx))

	refreshDone := make(chan error, 1)
	workers.Go(func() { refreshDone <- sql.New(refreshConn).RefreshCveWorkloadCounts(ctx) })
	require.Eventually(t, func() bool {
		var blocked bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND pid = $1)
		`, refreshConn.Conn().PgConn().PID()).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond, "count refresh must wait for the correction transaction")
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, <-refreshDone)
	var affected int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT affected_workloads FROM mv_cve_workload_counts WHERE cve_id = 'CGA-fjmw-f657-w678'
	`).Scan(&affected))
	require.Equal(t, 1, affected)
}

func TestChainguardCorrectionsCountsAndNewImages(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	q := sql.New(pool)
	const (
		cga = "CGA-fjmw-f657-w678"
		pkg = "pkg:apk/chainguard/glibc-2.44@2.44-r11?arch=x86_64&distro=20230214"
	)
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag, state) VALUES
			('image', 'v1', 'updated'), ('image', 'v2', 'updated'), ('image', 'v3', 'updated');
		INSERT INTO workloads (name, workload_type, namespace, cluster, image_name, image_tag, state) VALUES
			('one', 'app', 'team', 'dev', 'image', 'v1', 'updated'),
			('two', 'app', 'team', 'dev', 'image', 'v2', 'updated'),
			('three', 'app', 'team', 'dev', 'image', 'v3', 'updated');
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs) VALUES
			('CGA-fjmw-f657-w678', 'test', 'test', 'test', 1, '{}'),
			('CVE-MANUAL', 'test', 'test', 'test', 1, '{}');
		INSERT INTO vulnerabilities (image_name, image_tag, cve_id, package, source, latest_version) VALUES
			('image', 'v1', 'CGA-fjmw-f657-w678', 'pkg:apk/chainguard/glibc-2.44@2.44-r11?arch=x86_64&distro=20230214', 'test', ''),
			('image', 'v2', 'CGA-fjmw-f657-w678', 'pkg:apk/chainguard/glibc-2.44@2.44-r11?arch=x86_64&distro=20230214', 'test', ''),
			('image', 'v3', 'CGA-fjmw-f657-w678', 'pkg:apk/chainguard/glibc-2.44@2.44-r6?arch=x86_64&distro=20230214', 'test', ''),
			('image', 'v1', 'CVE-MANUAL', 'dependency', 'test', '');
		INSERT INTO suppressed_vulnerabilities (image_name, cve_id, package, suppressed, reason)
			VALUES ('image', 'CVE-MANUAL', 'dependency', TRUE, 'false_positive');
	`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		UPDATE vulnerabilities SET fix_version = '2.44-r7', fix_status = 'fix_available'
		WHERE image_name = 'image' AND image_tag = 'v1' AND cve_id = 'CGA-fjmw-f657-w678'
	`)
	require.NoError(t, err)

	refresh := func(tags ...string) {
		t.Helper()
		for _, tag := range tags {
			require.NoError(t, q.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
				ImageName: "image", ImageTag: tag,
			}))
		}
		require.NoError(t, q.RefreshCveWorkloadCounts(ctx))
	}
	assertRisk := func(tag string, expected int) {
		t.Helper()
		var risk int
		require.NoError(t, pool.QueryRow(ctx, "SELECT risk_score FROM vulnerability_summary WHERE image_name = $1 AND image_tag = $2", "image", tag).Scan(&risk))
		require.Equal(t, expected, risk)
	}
	assertCveCounts := func(expected int32) {
		t.Helper()
		live, err := q.ListCveSummaries(ctx, sql.ListCveSummariesParams{
			Limit: 50, ExcludeClusters: []string{}, ExcludeNamespaces: []string{},
		})
		require.NoError(t, err)
		require.Len(t, live, 1)
		require.Equal(t, cga, live[0].CveID)
		require.Equal(t, expected, live[0].AffectedWorkloads)
		cached, err := q.ListCveSummariesFromCounts(ctx, sql.ListCveSummariesFromCountsParams{
			Limit: 50, ExcludeClusters: []string{}, ExcludeNamespaces: []string{},
		})
		require.NoError(t, err)
		require.Len(t, cached, 1)
		require.Equal(t, cga, cached[0].CveID)
		require.Equal(t, expected, cached[0].AffectedWorkloads)
	}

	refresh("v1", "v2", "v3")
	assertRisk("v1", 5)
	assertCveCounts(3)

	correction := sql.SaveChainguardCorrectionParams{
		CveID: cga, Package: pkg, FixStatus: sql.FixStatusInstalledVersionFixed,
		SourceUrl: "https://advisories.cgr.dev/chainguard/v3/osv/" + cga + ".json",
	}
	require.NoError(t, q.SaveChainguardCorrection(ctx, correction))
	refresh("v1", "v2", "v3")
	assertRisk("v1", 0)
	assertRisk("v2", 0)
	assertRisk("v3", 5)
	assertCveCounts(1)

	findings, err := q.ListVulnerabilitiesForImage(ctx, sql.ListVulnerabilitiesForImageParams{
		ImageName: "image", ImageTag: "v1", Limit: 50,
	})
	require.NoError(t, err)
	require.Empty(t, findings)
	active, err := q.ListVulnerabilities(ctx, sql.ListVulnerabilitiesParams{Limit: 50})
	require.NoError(t, err)
	require.Len(t, active, 1)
	require.Equal(t, "v3", active[0].ImageTag)
	var id pgtype.UUID
	require.NoError(t, pool.QueryRow(ctx, "SELECT id FROM vulnerabilities WHERE image_name = $1 AND image_tag = $2 AND cve_id = $3", "image", "v1", cga).Scan(&id))
	detail, err := q.GetVulnerabilityById(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, detail.FixStatus)
	require.Equal(t, sql.FixStatusInstalledVersionFixed, *detail.FixStatus)

	workloads, err := q.ListWorkloadsForVulnerabilities(ctx, sql.ListWorkloadsForVulnerabilitiesParams{
		CveIds: []string{cga}, Limit: 50,
		Namespaces: []string{}, ExcludeNamespaces: []string{}, ExcludeClusters: []string{},
	})
	require.NoError(t, err)
	require.Len(t, workloads, 1)
	require.Equal(t, "three", workloads[0].WorkloadName)
	require.Equal(t, int32(1), workloads[0].WorkloadCount)

	_, err = pool.Exec(ctx, `
		INSERT INTO images (name, tag, state) VALUES ('image', 'v4', 'updated');
		INSERT INTO workloads (name, workload_type, namespace, cluster, image_name, image_tag, state)
		VALUES ('four', 'app', 'team', 'dev', 'image', 'v4', 'updated');
	`)
	require.NoError(t, err)
	batch := q.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{{
		ImageName: "image", ImageTag: "v4", CveID: cga, Package: pkg, Source: "test",
	}})
	batch.Exec(func(_ int, err error) { require.NoError(t, err) })
	refresh("v4")
	assertRisk("v4", 0)
	assertCveCounts(1)
	var storedStatus *sql.FixStatus
	require.NoError(t, pool.QueryRow(ctx, "SELECT fix_status FROM vulnerabilities WHERE image_name = $1 AND image_tag = $2", "image", "v4").Scan(&storedStatus))
	require.Nil(t, storedStatus)
	var assessments int
	require.NoError(t, pool.QueryRow(ctx, "SELECT COUNT(*) FROM chainguard_corrections WHERE advisory_id = $1 AND package_purl = $2", cga, pkg).Scan(&assessments))
	require.Equal(t, 1, assessments)

	correction.FixStatus = sql.FixStatusFixAvailable
	correction.FixVersion = "2.44-r12"
	require.NoError(t, q.SaveChainguardCorrection(ctx, correction))
	refresh("v1", "v2", "v4")
	assertRisk("v1", 5)
	assertRisk("v2", 5)
	assertRisk("v4", 5)
	assertCveCounts(4)

	correction.FixStatus = sql.FixStatusInstalledVersionFixed
	correction.FixVersion = ""
	require.NoError(t, q.SaveChainguardCorrection(ctx, correction))
	refresh("v1", "v2", "v4")
	assertCveCounts(1)
	require.NoError(t, q.ClearChainguardCorrections(ctx))
	refresh("v1", "v2", "v4")
	assertCveCounts(4)
	assertRisk("v1", 5)
	detail, err = q.GetVulnerabilityById(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, detail.FixStatus)
	require.Equal(t, sql.FixStatusUnknown, *detail.FixStatus)
	require.Nil(t, detail.FixVersion)
	var suppressed bool
	require.NoError(t, pool.QueryRow(ctx, "SELECT suppressed FROM suppressed_vulnerabilities WHERE cve_id = $1", "CVE-MANUAL").Scan(&suppressed))
	require.True(t, suppressed)
	var originalVersion *string
	require.NoError(t, pool.QueryRow(ctx, "SELECT fix_version FROM vulnerabilities WHERE id = $1", id).Scan(&originalVersion))
	require.NotNil(t, originalVersion)
	require.Equal(t, "2.44-r7", *originalVersion)

	correction.FixStatus = sql.FixStatusInstalledVersionFixed
	require.NoError(t, q.SaveChainguardCorrection(ctx, correction))
	_, err = pool.Exec(ctx, `
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs)
			VALUES ('CGA-aaaa-bbbb-cccc', 'test', 'test', 'test', 1, '{}');
		INSERT INTO cve_alias (alias, canonical_cve_id)
			VALUES ('CGA-aaaa-bbbb-cccc', 'CGA-fjmw-f657-w678');
		INSERT INTO vulnerabilities (image_name, image_tag, cve_id, package, source, latest_version)
			VALUES ('image', 'v1', 'CGA-aaaa-bbbb-cccc',
				'pkg:apk/chainguard/glibc-2.44@2.44-r11?arch=x86_64&distro=20230214', 'test', '');
	`)
	require.NoError(t, err)
	refresh("v1", "v2", "v4")
	assertCveCounts(2)
	assertRisk("v1", 5)
	findings, err = q.ListVulnerabilitiesForImage(ctx, sql.ListVulnerabilitiesForImageParams{
		ImageName: "image", ImageTag: "v1", Limit: 50,
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Nil(t, findings[0].FixStatus)
	workloads, err = q.ListWorkloadsForVulnerabilities(ctx, sql.ListWorkloadsForVulnerabilitiesParams{
		CveIds: []string{cga}, Limit: 50,
		Namespaces: []string{}, ExcludeNamespaces: []string{}, ExcludeClusters: []string{},
	})
	require.NoError(t, err)
	require.Len(t, workloads, 2)
}
