package osv

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
)

const (
	workerCount    = 20
	BatchSize      = 1000
	OsvSyncLockKey = int64(7705370000)
)

type Fetcher struct {
	client  *Client
	pool    *pgxpool.Pool
	querier sql.Querier
	log     *logrus.Entry
}

func NewFetcherWithClient(client *Client, pool *pgxpool.Pool, log *logrus.Entry) *Fetcher {
	return &Fetcher{client: client, pool: pool, log: log}
}

func NewFetcherWithQuerier(client *Client, querier sql.Querier, log *logrus.Entry) *Fetcher {
	return &Fetcher{client: client, querier: querier, log: log}
}

type fixResult struct {
	cveID      string
	pkg        string
	fixVersion string
}

func (f *Fetcher) Sync(ctx context.Context) error {
	if f.client.baseURL == "" {
		f.log.Warn("OSV_BASE_URL is not set, skipping OSV sync")
		return nil
	}
	f.log.Info("starting OSV fix-version sync")
	start := time.Now()

	var querier sql.Querier
	var conn *pgxpool.Conn
	if f.pool != nil {
		var err error
		conn, err = f.pool.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("acquiring DB connection for OSV sync: %w", err)
		}
		querier = sql.New(conn)
	} else {
		querier = f.querier
	}

	locked, err := querier.TryAdvisoryLock(ctx, OsvSyncLockKey)
	if err != nil {
		if conn != nil {
			conn.Release()
		}
		return fmt.Errorf("acquiring OSV sync advisory lock: %w", err)
	}
	if !locked {
		if conn != nil {
			conn.Release()
		}
		f.log.Info("OSV sync already running on another pod, skipping")
		return nil
	}

	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		released, unlockErr := querier.AdvisoryUnlock(unlockCtx, OsvSyncLockKey)
		if unlockErr != nil {
			f.log.WithError(unlockErr).Warn("failed to release OSV sync advisory lock, discarding connection")
			if conn != nil {
				if closeErr := conn.Hijack().Close(context.Background()); closeErr != nil {
					f.log.WithError(closeErr).Warn("failed to close connection after advisory unlock failure")
				}
			}
			return
		}
		if !released {
			f.log.Warn("OSV sync advisory lock was not held at unlock time")
		}
		if conn != nil {
			conn.Release()
		}
	}()

	rows, err := querier.GetVulnerabilitiesForOsvEnrichment(ctx)
	if err != nil {
		return fmt.Errorf("loading vulnerabilities for OSV enrichment: %w", err)
	}
	if len(rows) == 0 {
		f.log.Info("no vulnerabilities to enrich with OSV fix versions")
		return nil
	}

	byCve := groupByCve(rows)
	f.log.Infof("OSV sync: %d distinct CVE IDs to query (%d cve/package pairs)", len(byCve), len(rows))

	fetchStart := time.Now()
	results, errors, misses := f.fetchAll(ctx, byCve)
	hits := int64(len(results)) - misses
	f.log.Infof("OSV sync: fetched %d CVEs in %s (%d hits, %d misses, %d fetch errors)",
		len(byCve), time.Since(fetchStart).Round(time.Millisecond), hits, misses, errors)

	if err := f.persist(ctx, querier, results); err != nil {
		return err
	}
	f.log.Infof("OSV sync complete in %s", time.Since(start).Round(time.Millisecond))
	return nil
}

func (f *Fetcher) fetchAll(ctx context.Context, byCve map[string][]string) ([]fixResult, int64, int64) {
	jobs := make(chan string, len(byCve))
	out := make(chan fixResult, len(byCve)*2)

	var fetchErrors, fetchMisses atomic.Int64
	var wg sync.WaitGroup

	for range workerCount {
		wg.Go(func() {
			for cveID := range jobs {
				f.processCve(ctx, cveID, byCve[cveID], out, &fetchErrors, &fetchMisses)
			}
		})
	}

	for id := range byCve {
		jobs <- id
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(out)
	}()

	var results []fixResult
	for r := range out {
		results = append(results, r)
	}
	return results, fetchErrors.Load(), fetchMisses.Load()
}

func (f *Fetcher) processCve(ctx context.Context, cveID string, pkgs []string, out chan<- fixResult, errors, misses *atomic.Int64) {
	record, err := f.client.FetchVuln(ctx, cveID)
	if err != nil {
		f.log.WithError(err).Warnf("OSV fetch failed for %s", cveID)
		errors.Add(int64(len(pkgs)))
		return
	}
	if record == nil {
		for _, pkg := range pkgs {
			out <- fixResult{cveID: cveID, pkg: pkg}
			misses.Add(1)
		}
		return
	}

	record = f.mergeAliases(ctx, cveID, record)

	for _, pkg := range pkgs {
		fv := FixVersionForPurl(record, pkg)
		out <- fixResult{cveID: cveID, pkg: pkg, fixVersion: fv}
		if fv == "" {
			misses.Add(1)
		}
	}
}

// mergeAliases follows non-CVE aliases (GHSA-, GO-, PYSEC-, ...) and merges their Affected data —
// a CVE-numbered record is often just a stub pointing at the record with real fix-version data.
func (f *Fetcher) mergeAliases(ctx context.Context, cveID string, record *VulnRecord) *VulnRecord {
	for _, alias := range record.Aliases {
		if alias == cveID || strings.HasPrefix(alias, "CVE-") {
			continue
		}
		aliasRecord, err := f.client.FetchVuln(ctx, alias)
		if err != nil {
			f.log.WithError(err).Warnf("OSV fetch failed for alias %s of %s", alias, cveID)
			continue
		}
		if aliasRecord != nil {
			record.Affected = append(record.Affected, aliasRecord.Affected...)
		}
	}
	return record
}

func (f *Fetcher) persist(ctx context.Context, querier sql.Querier, results []fixResult) error {
	var (
		updateCveIDs   []string
		updatePackages []string
		updateFixes    []string
		clearCveIDs    []string
		clearPackages  []string
	)
	for _, r := range results {
		if r.fixVersion == "" {
			clearCveIDs = append(clearCveIDs, r.cveID)
			clearPackages = append(clearPackages, r.pkg)
		} else {
			updateCveIDs = append(updateCveIDs, r.cveID)
			updatePackages = append(updatePackages, r.pkg)
			updateFixes = append(updateFixes, r.fixVersion)
		}
	}

	var totalUpdated, totalCleared int64

	for i := 0; i < len(updateCveIDs); i += BatchSize {
		end := min(i+BatchSize, len(updateCveIDs))
		n, err := querier.BulkUpdateFixVersions(ctx, sql.BulkUpdateFixVersionsParams{
			CveIds:      updateCveIDs[i:end],
			Packages:    updatePackages[i:end],
			FixVersions: updateFixes[i:end],
		})
		if err != nil {
			return fmt.Errorf("bulk updating fix versions: %w", err)
		}
		totalUpdated += n
	}

	for i := 0; i < len(clearCveIDs); i += BatchSize {
		end := min(i+BatchSize, len(clearCveIDs))
		n, err := querier.BulkClearFixVersions(ctx, sql.BulkClearFixVersionsParams{
			CveIds:   clearCveIDs[i:end],
			Packages: clearPackages[i:end],
		})
		if err != nil {
			return fmt.Errorf("bulk clearing stale fix versions: %w", err)
		}
		totalCleared += n
	}

	f.log.Infof("OSV sync complete: %d rows updated, %d stale rows cleared", totalUpdated, totalCleared)
	return nil
}

func groupByCve(rows []*sql.GetVulnerabilitiesForOsvEnrichmentRow) map[string][]string {
	byCve := make(map[string][]string, len(rows))
	for _, r := range rows {
		byCve[r.CveID] = append(byCve[r.CveID], r.Package)
	}
	return byCve
}
