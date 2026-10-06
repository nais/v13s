package commands

import (
	"context"
	"testing"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

type fakeImageVulnerabilityLister struct {
	pages [][]*vulnerabilities.Vulnerability
	calls int
}

func (f *fakeImageVulnerabilityLister) ListVulnerabilitiesForImage(_ context.Context, _, _ string, _ ...vulnerabilities.Option) (*vulnerabilities.ListVulnerabilitiesForImageResponse, error) {
	page := f.pages[f.calls]
	f.calls++
	return &vulnerabilities.ListVulnerabilitiesForImageResponse{
		Nodes:    page,
		PageInfo: &vulnerabilities.PageInfo{HasNextPage: f.calls < len(f.pages)},
	}, nil
}

func TestFindVulnerabilityID(t *testing.T) {
	canonical := &vulnerabilities.Vulnerability{
		Id:      "vuln-canonical",
		Package: "pkg-a",
		Cve: &vulnerabilities.Cve{
			Id:         "CVE-2024-0001",
			References: map[string]string{"CVE-2024-0001": "GHSA-aaaa-bbbb-cccc"},
		},
	}
	other := &vulnerabilities.Vulnerability{
		Id:      "vuln-other",
		Package: "pkg-b",
		Cve:     &vulnerabilities.Cve{Id: "CVE-2024-0002"},
	}
	unrelatedRefs := &vulnerabilities.Vulnerability{
		Id:      "vuln-unrelated-refs",
		Package: "pkg-a",
		Cve: &vulnerabilities.Cve{
			Id:         "CVE-2024-0003",
			References: map[string]string{"CVE-2024-0004": "GHSA-dddd-eeee-ffff"},
		},
	}
	samePkgTarget := &vulnerabilities.Vulnerability{
		Id:      "vuln-target",
		Package: "pkg-a",
		Cve: &vulnerabilities.Cve{
			Id:         "CVE-2024-0004",
			References: map[string]string{"CVE-2024-0004": "GHSA-dddd-eeee-ffff"},
		},
	}

	tests := []struct {
		name    string
		pages   [][]*vulnerabilities.Vulnerability
		pkg     string
		cveID   string
		wantID  string
		wantErr bool
	}{
		{
			name:   "matches canonical id",
			pages:  [][]*vulnerabilities.Vulnerability{{other, canonical}},
			pkg:    "pkg-a",
			cveID:  "CVE-2024-0001",
			wantID: "vuln-canonical",
		},
		{
			name:   "matches alias resolved to canonical",
			pages:  [][]*vulnerabilities.Vulnerability{{canonical}},
			pkg:    "pkg-a",
			cveID:  "GHSA-aaaa-bbbb-cccc",
			wantID: "vuln-canonical",
		},
		{
			name:   "matches on a later page",
			pages:  [][]*vulnerabilities.Vulnerability{{other}, {canonical}},
			pkg:    "pkg-a",
			cveID:  "cve-2024-0001",
			wantID: "vuln-canonical",
		},
		{
			name:   "ignores reference pair belonging to another cve",
			pages:  [][]*vulnerabilities.Vulnerability{{unrelatedRefs, samePkgTarget}},
			pkg:    "pkg-a",
			cveID:  "GHSA-dddd-eeee-ffff",
			wantID: "vuln-target",
		},
		{
			name:    "ignores canonical key of another cve",
			pages:   [][]*vulnerabilities.Vulnerability{{unrelatedRefs}},
			pkg:     "pkg-a",
			cveID:   "CVE-2024-0004",
			wantErr: true,
		},
		{
			name:    "package must match",
			pages:   [][]*vulnerabilities.Vulnerability{{canonical}},
			pkg:     "pkg-b",
			cveID:   "CVE-2024-0001",
			wantErr: true,
		},
		{
			name:    "not found",
			pages:   [][]*vulnerabilities.Vulnerability{{other}},
			pkg:     "pkg-a",
			cveID:   "CVE-2024-9999",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := &fakeImageVulnerabilityLister{pages: tt.pages}
			got, err := findVulnerabilityID(context.Background(), lister, "image", "tag", tt.pkg, tt.cveID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got id %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantID {
				t.Fatalf("got %q, want %q", got, tt.wantID)
			}
		})
	}
}
