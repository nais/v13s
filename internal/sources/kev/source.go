package kev

import (
	"cmp"
	"context"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
)

const feedTimeout = 60 * time.Second

var noteURL = regexp.MustCompile(`https?://[^\s;"']+`)

type Assertion struct {
	CveID            string
	KnownRansomware  bool
	ShortDescription string
	ReferenceURLs    []string
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

func referenceURLs(notes string) []string {
	var urls []string
	for _, u := range noteURL.FindAllString(notes, -1) {
		u = strings.TrimRight(u, ",")
		if strings.Contains(u, "cisa.gov/news-events/directives/") || slices.Contains(urls, u) {
			continue
		}
		urls = append(urls, u)
	}
	return urls
}

type sourceEntry struct {
	cveID  string
	source string
}

func entries(bySource map[string][]Assertion) sql.UpsertKevSourceEntriesParams {
	merged := map[sourceEntry]Assertion{}
	for source, assertions := range bySource {
		for _, a := range assertions {
			if a.CveID == "" {
				continue
			}
			e := sourceEntry{cveID: a.CveID, source: source}
			m := merged[e]
			m.KnownRansomware = m.KnownRansomware || a.KnownRansomware
			m.ShortDescription = cmp.Or(m.ShortDescription, a.ShortDescription)
			for _, ref := range a.ReferenceURLs {
				if !slices.Contains(m.ReferenceURLs, ref) {
					m.ReferenceURLs = append(m.ReferenceURLs, ref)
				}
			}
			merged[e] = m
		}
	}

	var params sql.UpsertKevSourceEntriesParams
	sorted := slices.SortedFunc(maps.Keys(merged), func(a, b sourceEntry) int {
		return cmp.Or(cmp.Compare(a.cveID, b.cveID), cmp.Compare(a.source, b.source))
	})
	for _, e := range sorted {
		m := merged[e]
		params.CveIds = append(params.CveIds, e.cveID)
		params.Sources = append(params.Sources, e.source)
		params.KnownRansomwareUse = append(params.KnownRansomwareUse, m.KnownRansomware)
		params.ShortDescriptions = append(params.ShortDescriptions, m.ShortDescription)
		params.ReferenceUrls = append(params.ReferenceUrls, strings.Join(m.ReferenceURLs, "\n"))
	}
	return params
}
