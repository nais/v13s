package kev

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

func TestReferenceURLs(t *testing.T) {
	for _, test := range []struct {
		name  string
		notes string
		want  []string
	}{
		{
			name:  "double quoted URL",
			notes: `"https://nvd.nist.gov/vuln/detail/CVE-2026-41940"`,
			want:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-41940"},
		},
		{
			name:  "single quoted URL",
			notes: `'https://example.com/advisory'`,
			want:  []string{"https://example.com/advisory"},
		},
		{
			name:  "deduplicates quoted and unquoted references",
			notes: `https://example.com/advisory; "https://example.com/advisory"; https://www.cisa.gov/news-events/directives/bod-26-04`,
			want:  []string{"https://example.com/advisory"},
		},
		{
			name:  "comma separated references",
			notes: "https://example.com/advisory, https://example.com/report",
			want:  []string{"https://example.com/advisory", "https://example.com/report"},
		},
		{
			name:  "deduplicates references after removing separator commas",
			notes: "https://example.com/advisory, https://example.com/advisory",
			want:  []string{"https://example.com/advisory"},
		},
		{
			name:  "preserves commas inside URLs",
			notes: "https://example.com/report?ids=one,two",
			want:  []string{"https://example.com/report?ids=one,two"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := referenceURLs(test.notes); !slices.Equal(got, test.want) {
				t.Errorf("referenceURLs() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestEntriesMergeReferenceURLs(t *testing.T) {
	got := entries(map[string][]Assertion{
		"enisa": {
			{
				CveID:         "CVE-2026-1234",
				ReferenceURLs: []string{"https://example.com/advisory", "https://example.com/shared"},
			},
			{
				CveID:         "CVE-2026-1234",
				ReferenceURLs: []string{"https://example.com/shared", "https://example.com/report", "https://example.com/report"},
			},
		},
	})
	want := []string{"https://example.com/advisory\nhttps://example.com/shared\nhttps://example.com/report"}
	if !slices.Equal(got.ReferenceUrls, want) {
		t.Errorf("entries().ReferenceUrls = %q, want %q", got.ReferenceUrls, want)
	}
}

func TestReferenceURLsCatalogFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/kev_catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog Catalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	for _, entry := range catalog.Vulnerabilities {
		if entry.CveID != "CVE-2026-41940" {
			continue
		}
		want := []string{
			"https://support.cpanel.net/hc/en-us/articles/40073787579671-cPanel-WHM-Security-Update-04-28-2026",
			"https://docs.cpanel.net/release-notes/release-notes/",
			"https://docs.wpsquared.com/changelogs/versions/changelog/#13617",
			"https://nvd.nist.gov/vuln/detail/CVE-2026-41940",
		}
		if got := referenceURLs(entry.Notes); !slices.Equal(got, want) {
			t.Errorf("referenceURLs() = %q, want %q", got, want)
		}
		return
	}
	t.Fatal("CVE-2026-41940 is missing from the fixture")
}
