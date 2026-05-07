package osv

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
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

type fixTarget struct {
	id  pgtype.UUID
	pkg string
}

type fixResult struct {
	id         pgtype.UUID
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
	if f.pool != nil {
		conn, err := f.pool.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("acquiring DB connection for OSV sync: %w", err)
		}
		defer func() {
			unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			released, err := querier.AdvisoryUnlock(unlockCtx, OsvSyncLockKey)
			if err != nil {
				f.log.WithError(err).Warn("failed to release OSV sync advisory lock, discarding connection")
				conn.Hijack().Close(context.Background())
				return
			}
			if !released {
				f.log.Warn("OSV sync advisory lock was not held at unlock time")
			}
			conn.Release()
		}()
		querier = sql.New(conn)
	} else {
		querier = f.querier
	}

	locked, err := querier.TryAdvisoryLock(ctx, OsvSyncLockKey)
	if err != nil {
		return fmt.Errorf("acquiring OSV sync advisory lock: %w", err)
	}
	if !locked {
		f.log.Info("OSV sync already running on another pod, skipping")
		return nil
	}

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

func (f *Fetcher) fetchAll(ctx context.Context, byCve map[string][]fixTarget) ([]fixResult, int64, int64) {
	jobs := make(chan string, len(byCve))
	out := make(chan fixResult, len(byCve)*2)

	var fetchErrors, fetchMisses atomic.Int64
	var wg sync.WaitGroup

	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cveID := range jobs {
				f.processCve(ctx, cveID, byCve[cveID], out, &fetchErrors, &fetchMisses)
			}
		}()
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

func (f *Fetcher) processCve(ctx context.Context, cveID string, targets []fixTarget, out chan<- fixResult, errors, misses *atomic.Int64) {
	record, err := f.client.FetchVuln(ctx, cveID)
	if err != nil {
		f.log.WithError(err).Warnf("OSV fetch failed for %s", cveID)
		errors.Add(int64(len(targets)))
		return
	}
	if record == nil {
		for _, t := range targets {
			out <- fixResult{id: t.id, cveID: cveID, pkg: t.pkg}
			misses.Add(1)
		}
		return
	}

	record = f.mergeAliases(ctx, cveID, record)

	fvByPkg := make(map[string]string)
	for _, t := range targets {
		fv, seen := fvByPkg[t.pkg]
		if !seen {
			fv = FixVersionForPurl(record, t.pkg)
			fvByPkg[t.pkg] = fv
		}
		out <- fixResult{id: t.id, cveID: cveID, pkg: t.pkg, fixVersion: fv}
		if fv == "" {
			misses.Add(1)
		}
	}
}

func (f *Fetcher) mergeAliases(ctx context.Context, cveID string, record *VulnRecord) *VulnRecord {
	for _, alias := range record.Aliases {
		if !isGHSA(alias) {
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
		updateIDs   []pgtype.UUID
		updateFixes []string
		clearIDs    []pgtype.UUID
	)
	for _, r := range results {
		if r.fixVersion == "" {
			clearIDs = append(clearIDs, r.id)
		} else {
			updateIDs = append(updateIDs, r.id)
			updateFixes = append(updateFixes, r.fixVersion)
		}
	}

	var totalUpdated, totalCleared int64

	for i := 0; i < len(updateIDs); i += BatchSize {
		end := min(i+BatchSize, len(updateIDs))
		n, err := querier.BulkUpdateFixVersions(ctx, sql.BulkUpdateFixVersionsParams{
			VulnerabilityIds: updateIDs[i:end],
			FixVersions:      updateFixes[i:end],
		})
		if err != nil {
			return fmt.Errorf("bulk updating fix versions: %w", err)
		}
		totalUpdated += n
	}

	for i := 0; i < len(clearIDs); i += BatchSize {
		end := min(i+BatchSize, len(clearIDs))
		n, err := querier.BulkClearFixVersions(ctx, clearIDs[i:end])
		if err != nil {
			return fmt.Errorf("bulk clearing stale fix versions: %w", err)
		}
		totalCleared += n
	}

	f.log.Infof("OSV sync complete: %d rows updated, %d stale rows cleared", totalUpdated, totalCleared)
	return nil
}

func groupByCve(rows []*sql.GetVulnerabilitiesForOsvEnrichmentRow) map[string][]fixTarget {
	byCve := make(map[string][]fixTarget, len(rows))
	for _, r := range rows {
		byCve[r.CveID] = append(byCve[r.CveID], fixTarget{id: r.ID, pkg: r.Package})
	}
	return byCve
}
