package osv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/package-url/packageurl-go"
)

const chainguardAdvisoryHost = "advisories.cgr.dev"

var (
	chainguardID         = regexp.MustCompile(`^CGA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`)
	supportedAPKRevision = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*-r[0-9]+$`)
)

type chainguardMode int

const (
	chainguardIgnored chainguardMode = iota
	chainguardCorrect
	chainguardClear
)

type chainguardClient struct {
	httpClient *http.Client
}

func newChainguardClient() *chainguardClient {
	return &chainguardClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 || req.URL.Scheme != "https" || req.URL.Host != chainguardAdvisoryHost {
					return errors.New("invalid redirect from Chainguard advisory source")
				}
				return nil
			},
		},
	}
}

func chainguardAdvisoryURL(id string) string {
	return "https://" + chainguardAdvisoryHost + "/chainguard/v3/osv/" + id + ".json"
}

func (c *chainguardClient) fetch(ctx context.Context, id string) (*VulnRecord, error) {
	if !chainguardID.MatchString(id) {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chainguardAdvisoryURL(id), nil)
	if err != nil {
		return nil, fmt.Errorf("building Chainguard request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching Chainguard advisory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching Chainguard advisory: HTTP %d", resp.StatusCode)
	}
	resp.Body = io.NopCloser(io.LimitReader(resp.Body, 4<<20))
	return decodeVulnRecord(id, resp)
}

func chainguardFix(record *VulnRecord, id, rawPurl string) (string, MissReason) {
	if record == nil || record.ID != id || !chainguardID.MatchString(id) || record.Withdrawn != nil {
		return "", MissUnknown
	}
	pkg, err := packageurl.FromString(rawPurl)
	if err != nil || pkg.Type != purlTypeApk || pkg.Subpath != "" {
		return "", MissUnknown
	}
	ecosystem := apkEcosystems[pkg.Namespace]
	if ecosystem == "" || pkg.Qualifiers.Map()["arch"] == "" {
		return "", MissUnknown
	}
	if !supportedAPKRevision.MatchString(pkg.Version) {
		return "", MissUnknown
	}

	filtered := &VulnRecord{ID: id}
	hasFixed := false
	for _, affected := range record.Affected {
		if affected.Package.Ecosystem != ecosystem || affected.Package.Name != pkg.Name {
			continue
		}
		other, err := packageurl.FromString(affected.Package.Purl)
		if err != nil || other.Type != pkg.Type || other.Namespace != pkg.Namespace ||
			other.Name != pkg.Name || other.Subpath != "" ||
			(other.Version != "" && other.Version != pkg.Version) {
			return "", MissUnknown
		}
		if other.Qualifiers.Map()["arch"] == "" {
			return "", MissUnknown
		}
		if other.Qualifiers.Map()["arch"] != pkg.Qualifiers.Map()["arch"] {
			continue
		}
		for key, value := range other.Qualifiers.Map() {
			if pkg.Qualifiers.Map()[key] != value {
				return "", MissUnknown
			}
		}
		if !validChainguardRanges(affected) {
			return "", MissUnknown
		}
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				hasFixed = hasFixed || event.Fixed != ""
			}
		}
		filtered.Affected = append(filtered.Affected, affected)
	}
	if len(filtered.Affected) == 0 {
		return "", MissPackageNotListed
	}
	fix, miss := FixVersionForPurl(filtered, rawPurl)
	if miss == MissInstalledPastFix && !hasFixed {
		return "", MissUnknown
	}
	return fix, miss
}

func validChainguardRanges(affected Affected) bool {
	if len(affected.Ranges) == 0 {
		return false
	}
	for _, raw := range affected.Versions {
		if !supportedAPKRevision.MatchString(raw) {
			return false
		}
	}
	for _, r := range affected.Ranges {
		if r.Type != rangeTypeEcosystem || len(r.Events) == 0 {
			return false
		}
		for _, event := range r.Events {
			if event.LastAffected != "" || (event.Introduced == "" && !hasEnd(event)) {
				return false
			}
			if (event.Introduced != "" && event.Introduced != "0" && !supportedAPKRevision.MatchString(event.Introduced)) ||
				(event.Fixed != "" && !supportedAPKRevision.MatchString(event.Fixed)) {
				return false
			}
		}
		intervals, ok := parseIntervals(r.Events, purlTypeApk)
		if !ok {
			return false
		}
		for _, interval := range intervals {
			if !interval.open && !interval.fromBeginning &&
				(interval.end.LT(interval.start) || (!interval.endInclusive && !interval.end.GT(interval.start))) {
				return false
			}
		}
	}
	return true
}

func (f *Fetcher) processChainguard(ctx context.Context, id string, packages []string, out chan<- fixResult, fetchErrors *atomic.Int64) {
	record, err := f.chainguard.fetch(ctx, id)
	if err != nil {
		f.log.WithError(err).Warn("Chainguard advisory lookup failed")
		fetchErrors.Add(int64(len(packages)))
		record = nil
	}
	for _, pkg := range packages {
		fix, miss := chainguardFix(record, id, pkg)
		out <- fixResult{cveID: id, pkg: pkg, fixVersion: fix, miss: miss}
	}
}

func (f *Fetcher) syncChainguard(ctx context.Context, querier sql.Querier, conn *pgxpool.Conn) error {
	var results []fixResult
	if f.chainguardMode == chainguardCorrect {
		rows, err := querier.GetVulnerabilitiesForChainguardCorrection(ctx)
		if err != nil {
			return fmt.Errorf("loading Chainguard findings: %w", err)
		}
		packagesByID := make(map[string][]string)
		for _, row := range rows {
			packagesByID[row.CveID] = append(packagesByID[row.CveID], row.Package)
		}
		fetchStart := time.Now()
		var fetchErrors int64
		results, fetchErrors = f.fetchAll(ctx, packagesByID, f.processChainguard)
		f.log.Infof("Chainguard corrections: fetched %d advisories in %s (%d advisory/package pairs, %d fetch errors)",
			len(packagesByID), time.Since(fetchStart).Round(time.Millisecond), len(rows), fetchErrors)
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	if conn != nil {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("starting Chainguard correction transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		txQuerier := sql.New(tx)
		if err := txQuerier.LockChainguardCorrections(ctx); err != nil {
			return fmt.Errorf("locking Chainguard corrections: %w", err)
		}
		if err := f.persistChainguard(ctx, txQuerier, results); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	return f.persistChainguard(ctx, querier, results)
}

func (f *Fetcher) persistChainguard(ctx context.Context, querier sql.Querier, results []fixResult) error {
	if f.chainguardMode == chainguardClear {
		if err := querier.ClearChainguardCorrections(ctx); err != nil {
			return fmt.Errorf("clearing disabled Chainguard corrections: %w", err)
		}
	}
	for _, result := range results {
		if err := querier.SaveChainguardCorrection(ctx, sql.SaveChainguardCorrectionParams{
			CveID:      result.cveID,
			Package:    result.pkg,
			FixStatus:  fixStatusFor(result.miss),
			FixVersion: result.fixVersion,
			SourceUrl:  chainguardAdvisoryURL(result.cveID),
		}); err != nil {
			return fmt.Errorf("saving Chainguard correction: %w", err)
		}
	}
	images, err := querier.ListImagesWithChainguardCorrections(ctx)
	if err != nil {
		return fmt.Errorf("loading images with Chainguard corrections: %w", err)
	}
	for _, image := range images {
		if err := querier.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
			ImageName: image.ImageName,
			ImageTag:  image.ImageTag,
		}); err != nil {
			return fmt.Errorf("recalculating Chainguard vulnerability summary: %w", err)
		}
	}
	if len(images) > 0 {
		if err := querier.RefreshCveWorkloadCounts(ctx); err != nil {
			return fmt.Errorf("refreshing corrected CVE counts: %w", err)
		}
	}
	return nil
}
