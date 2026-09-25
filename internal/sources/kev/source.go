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
	if cfg.VulnCheckEnabled {
		sources = append(sources, NewVulnCheckClient(cfg.VulnCheckURL, cfg.VulnCheckToken))
	}
	return sources
}

type sourceEntry struct {
	cveID  string
	source string
}

func entries(bySource map[string][]Assertion) sql.UpsertKevSourceEntriesParams {
	ransomware := map[sourceEntry]bool{}
	for source, assertions := range bySource {
		for _, a := range assertions {
			if a.CveID == "" {
				continue
			}
			e := sourceEntry{cveID: a.CveID, source: source}
			ransomware[e] = ransomware[e] || a.KnownRansomware
		}
	}

	var params sql.UpsertKevSourceEntriesParams
	sorted := slices.SortedFunc(maps.Keys(ransomware), func(a, b sourceEntry) int {
		return cmp.Or(cmp.Compare(a.cveID, b.cveID), cmp.Compare(a.source, b.source))
	})
	for _, e := range sorted {
		params.CveIds = append(params.CveIds, e.cveID)
		params.Sources = append(params.Sources, e.source)
		params.KnownRansomwareUse = append(params.KnownRansomwareUse, ransomware[e])
	}
	return params
}
