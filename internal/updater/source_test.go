package updater

import (
	"testing"

	"github.com/nais/v13s/internal/sources"
	"github.com/stretchr/testify/assert"
)

func TestToCveSqlParams_EpssFields(t *testing.T) {
	cvss1, epss1, epssP1 := 8.7, 0.00516, 0.6674
	cvss2 := 7.5

	tests := []struct {
		name            string
		vuln            *sources.Vulnerability
		wantCvss        *float64
		wantEpssScore   *float64
		wantEpssPercent *float64
	}{
		{
			name: "all scores present",
			vuln: &sources.Vulnerability{
				Cve:            &sources.Cve{Id: "CVE-2025-10492", Severity: sources.SeverityHigh},
				CvssScore:      &cvss1,
				EpssScore:      &epss1,
				EpssPercentile: &epssP1,
			},
			wantCvss:        &cvss1,
			wantEpssScore:   &epss1,
			wantEpssPercent: &epssP1,
		},
		{
			name: "no epss scores",
			vuln: &sources.Vulnerability{
				Cve:       &sources.Cve{Id: "GHSA-3vqj-43w4-2q58", Severity: sources.SeverityHigh},
				CvssScore: &cvss2,
			},
			wantCvss:        &cvss2,
			wantEpssScore:   nil,
			wantEpssPercent: nil,
		},
		{
			name: "no scores at all",
			vuln: &sources.Vulnerability{
				Cve: &sources.Cve{Id: "GHSA-0000-0000-0000", Severity: sources.SeverityUnassigned},
			},
			wantCvss:        nil,
			wantEpssScore:   nil,
			wantEpssPercent: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &ImageVulnerabilityData{
				ImageName:       "my-image",
				ImageTag:        "1.0.0",
				Source:          "DependencyTrack",
				Vulnerabilities: []*sources.Vulnerability{tt.vuln},
			}

			params := data.ToCveSqlParams()
			assert.Len(t, params, 1)
			p := params[0]
			assert.Equal(t, tt.vuln.Cve.Id, p.CveID)
			assert.Equal(t, tt.wantCvss, p.CvssScore)
			assert.Equal(t, tt.wantEpssScore, p.EpssScore)
			assert.Equal(t, tt.wantEpssPercent, p.EpssPercentile)
		})
	}
}
