package suppressionforwarding

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources/osv"
)

const advisoryCacheTTL = time.Hour

var chainguardAdvisoryID = regexp.MustCompile(`^CGA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`)

type AdvisoryFetcher interface {
	FetchVuln(ctx context.Context, id string) (*osv.VulnRecord, error)
}

type cachedAdvisory struct {
	record    *osv.VulnRecord
	fetchedAt time.Time
}

type Upstream struct {
	fetcher AdvisoryFetcher
	now     func() time.Time
	mu      sync.Mutex
	cache   map[string]cachedAdvisory
}

func NewUpstream(fetcher AdvisoryFetcher) *Upstream {
	return &Upstream{fetcher: fetcher, now: time.Now, cache: map[string]cachedAdvisory{}}
}

func (u *Upstream) IDs(ctx context.Context, ids []string, packageKey string) ([]string, error) {
	var upstream []string
	for _, id := range ids {
		if !chainguardAdvisoryID.MatchString(id) {
			continue
		}
		record, err := u.advisory(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, candidate := range packageUpstream(record, packageKey) {
			if !slices.Contains(ids, candidate) && !slices.Contains(upstream, candidate) {
				upstream = append(upstream, candidate)
			}
		}
	}
	if hasSameFamily(slices.Concat(ids, upstream), upstream) {
		return nil, nil
	}
	return upstream, nil
}

func (u *Upstream) identities(ctx context.Context, rows []*sql.SuppressedVulnerability, packageKey string, ids []string) ([]string, error) {
	extra, err := u.IDs(ctx, ids, packageKey)
	if err != nil {
		return nil, err
	}
	ids = slices.Concat(ids, extra)
	for _, row := range rows {
		if slices.Contains(ids, row.CveID) || !chainguardAdvisoryID.MatchString(row.CveID) {
			continue
		}
		if key, err := PackageKey(row.Package); err != nil || key != packageKey {
			continue
		}
		linked, err := u.IDs(ctx, []string{row.CveID}, packageKey)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(linked, func(id string) bool { return slices.Contains(ids, id) }) {
			ids = append(ids, row.CveID)
		}
	}
	return ids, nil
}

func (u *Upstream) advisory(ctx context.Context, id string) (*osv.VulnRecord, error) {
	u.mu.Lock()
	cached, ok := u.cache[id]
	u.mu.Unlock()
	if ok && u.now().Sub(cached.fetchedAt) < advisoryCacheTTL {
		return cached.record, nil
	}
	record, err := u.fetcher.FetchVuln(ctx, id)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	u.cache[id] = cachedAdvisory{record: record, fetchedAt: u.now()}
	u.mu.Unlock()
	return record, nil
}

func packageUpstream(record *osv.VulnRecord, packageKey string) []string {
	if record == nil || record.Withdrawn != "" || !affects(record, packageKey) {
		return nil
	}
	ids := slices.Concat(record.Upstream, record.Aliases)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if hasSameFamily(ids, ids) {
		return nil
	}
	return ids
}

func hasSameFamily(ids, candidates []string) bool {
	for _, candidate := range candidates {
		family := idFamily(candidate)
		for _, id := range ids {
			if id != candidate && idFamily(id) == family {
				return true
			}
		}
	}
	return false
}

func idFamily(id string) string {
	family, _, _ := strings.Cut(id, "-")
	return family
}

func affects(record *osv.VulnRecord, packageKey string) bool {
	return slices.ContainsFunc(record.Affected, func(a osv.Affected) bool {
		key, err := PackageKey(a.Package.Purl)
		return err == nil && key == packageKey
	})
}
