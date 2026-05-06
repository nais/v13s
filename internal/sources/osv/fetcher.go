package osv

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
)

const workerCount = 20

type Fetcher struct {
	client  *Client
	querier sql.Querier
	log     *logrus.Entry
}

func NewFetcherWithClient(client *Client, querier sql.Querier, log *logrus.Entry) *Fetcher {
	return &Fetcher{client: client, querier: querier, log: log}
}

type fixResult struct {
	cveID      string
	pkg        string
	fixVersion string
}

func (f *Fetcher) Sync(ctx context.Context) error {
	f.log.Info("starting OSV fix-version sync")

	rows, err := f.querier.GetVulnerabilitiesForOsvEnrichment(ctx)
	if err != nil {
		return fmt.Errorf("loading vulnerabilities for OSV enrichment: %w", err)
	}
	if len(rows) == 0 {
		f.log.Info("no vulnerabilities to enrich with OSV fix versions")
		return nil
	}

	byCve := groupByCve(rows)
	f.log.Infof("OSV sync: %d distinct CVE IDs to query (%d cve/package pairs)", len(byCve), len(rows))

	results, errors, misses := f.fetchAll(ctx, byCve)
	f.log.Infof("OSV sync: %d fix versions found, %d misses, %d fetch errors", len(results)-countEmpty(results), misses, errors)

	return f.persist(ctx, results)
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

// mergeAliases fetches GHSA aliases and merges their Affected entries into the record.
// CVE records often lack purl data; GHSA records carry it.
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

func (f *Fetcher) persist(ctx context.Context, results []fixResult) error {
	var (
		updateCveIDs, updatePkgs, updateFixes []string
		clearCveIDs, clearPkgs                []string
	)
	for _, r := range results {
		if r.fixVersion == "" {
			clearCveIDs = append(clearCveIDs, r.cveID)
			clearPkgs = append(clearPkgs, r.pkg)
		} else {
			updateCveIDs = append(updateCveIDs, r.cveID)
			updatePkgs = append(updatePkgs, r.pkg)
			updateFixes = append(updateFixes, r.fixVersion)
		}
	}

	if len(updateCveIDs) > 0 {
		updated, err := f.querier.BulkUpdateFixVersions(ctx, sql.BulkUpdateFixVersionsParams{
			CveIds:      updateCveIDs,
			Packages:    updatePkgs,
			FixVersions: updateFixes,
		})
		if err != nil {
			return fmt.Errorf("bulk updating fix versions: %w", err)
		}
		f.log.Infof("OSV sync complete: %d rows updated in DB", updated)
	} else {
		f.log.Info("OSV sync: no fix versions to write")
	}

	if len(clearCveIDs) > 0 {
		cleared, err := f.querier.BulkClearFixVersions(ctx, sql.BulkClearFixVersionsParams{
			CveIds:   clearCveIDs,
			Packages: clearPkgs,
		})
		if err != nil {
			return fmt.Errorf("bulk clearing stale fix versions: %w", err)
		}
		if cleared > 0 {
			f.log.Infof("OSV sync: cleared %d stale fix versions", cleared)
		}
	}

	return nil
}

func groupByCve(rows []*sql.GetVulnerabilitiesForOsvEnrichmentRow) map[string][]string {
	byCve := make(map[string][]string, len(rows))
	for _, r := range rows {
		byCve[r.CveID] = append(byCve[r.CveID], r.Package)
	}
	return byCve
}

func countEmpty(results []fixResult) int {
	n := 0
	for _, r := range results {
		if r.fixVersion == "" {
			n++
		}
	}
	return n
}
