package kev

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
)

const feedTimeout = 60 * time.Second

type Assertion struct {
	CveID           string
	KnownRansomware bool
}

type Source interface {
	Name() string
	Fetch(ctx context.Context) ([]Assertion, error)
}

func SourcesFromConfig(cfg config.KevConfig) []Source {
	var sources []Source
	if cfg.CatalogURL != "" {
		sources = append(sources, NewCisaClient(cfg.CatalogURL))
	}
	if cfg.EnisaURL != "" {
		sources = append(sources, NewEnisaClient(cfg.EnisaURL))
	}
	if cfg.VulnCheckEnabled && cfg.VulnCheckToken != "" {
		sources = append(sources, NewVulnCheckClient(cfg.VulnCheckURL, cfg.VulnCheckToken))
	}
	return sources
}

type sourcePair struct {
	cveID  string
	source string
}

// merge marks a CVE as known exploited, or ransomware, when any source says so.
func merge(bySource map[string][]Assertion) (params sql.BulkUpdateKevDataParams, ransomwareCount int) {
	ransomware := map[string]bool{}
	pairs := map[sourcePair]struct{}{}
	for source, assertions := range bySource {
		for _, a := range assertions {
			if a.CveID == "" {
				continue
			}
			ransomware[a.CveID] = ransomware[a.CveID] || a.KnownRansomware
			pairs[sourcePair{cveID: a.CveID, source: source}] = struct{}{}
		}
	}

	params.CveIds = slices.Sorted(maps.Keys(ransomware))
	for _, id := range params.CveIds {
		params.KnownRansomwareUse = append(params.KnownRansomwareUse, ransomware[id])
		if ransomware[id] {
			ransomwareCount++
		}
	}

	sorted := slices.SortedFunc(maps.Keys(pairs), func(a, b sourcePair) int {
		return cmp.Or(cmp.Compare(a.cveID, b.cveID), cmp.Compare(a.source, b.source))
	})
	for _, p := range sorted {
		params.SourceCveIds = append(params.SourceCveIds, p.cveID)
		params.SourceNames = append(params.SourceNames, p.source)
	}
	return params, ransomwareCount
}
