package github

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCertificateIdentity(t *testing.T) {
	for _, tt := range []struct {
		name        string
		enabled     bool
		serverUrl   string
		orgs        []string
		workFlowRef string
		fails       bool
	}{
		{
			name:        "GitHub Cert Authz is enabled and matches pattern git ref",
			enabled:     true,
			serverUrl:   "https://github.com",
			orgs:        []string{"nais"},
			workFlowRef: "nais/yolo-bolo/.github/workflows/.main.yml@refs/heads/master",
		},
		{
			name:        "GitHub Cert Authz is enabled and matches pattern",
			enabled:     true,
			serverUrl:   "https://github.com",
			orgs:        []string{"nais"},
			workFlowRef: "nais/sapo/.github/workflows/PROD%20deploy.yml@refs/heads/sapo-upgrade",
		},
		{
			name:        "GitHub Cert Authz is enabled and matches pattern pull request",
			enabled:     true,
			serverUrl:   "https://github.com",
			orgs:        []string{"navikt"},
			workFlowRef: "navikt/yolo-bolo/.github/workflows/.build.yaml@refs/pull/1575/merge",
		},

		{
			name:        "GitHub Cert Authz is enabled and matches pattern tags",
			enabled:     true,
			serverUrl:   "https://github.com",
			orgs:        []string{"tull"},
			workFlowRef: "tull/yolo-bolo/.github/workflows/.build.yaml@refs/tags/1575/merge",
		},
		{
			name:        "GitHub Cert Authz is enabled and fails pattern",
			enabled:     true,
			serverUrl:   "https://github.com",
			orgs:        []string{"tull"},
			workFlowRef: "evilorg/yolo-bolo/.github/workflows/.build.yaml@refs/ta/1575/merge",
			fails:       true,
		},
		{
			name: "GitHub Cert Authz is disabled",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			id := NewCertificateIdentity(tt.orgs)
			idPattern := id.GetIdentities()
			for _, pattern := range idPattern {
				if tt.fails {
					assert.NotRegexp(t, pattern.SubjectRegExp, tt.serverUrl+"/"+tt.workFlowRef)
				} else {
					assert.Regexp(t, pattern.SubjectRegExp, tt.serverUrl+"/"+tt.workFlowRef)
				}
			}
		})
	}
}
