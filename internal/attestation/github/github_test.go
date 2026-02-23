package github

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateIdentity_GetIdentities_EmptyOrgs_ReturnsNone(t *testing.T) {
	t.Run("nil org slice", func(t *testing.T) {
		id := NewCertificateIdentity(nil)
		ids := id.GetIdentities()
		require.Len(t, ids, 0)
	})

	t.Run("empty org slice", func(t *testing.T) {
		id := NewCertificateIdentity([]string{})
		ids := id.GetIdentities()
		require.Len(t, ids, 0)
	})
}

func TestCertificateIdentity_GetIdentities_SingleIdentityForOrgList(t *testing.T) {
	id := NewCertificateIdentity([]string{"nais", "navikt"})
	ids := id.GetIdentities()

	require.Len(t, ids, 1)
	assert.Equal(t, IssuerUrl, ids[0].Issuer)
	assert.NotEmpty(t, ids[0].SubjectRegExp)

	// matches allowed orgs
	assert.Regexp(t, ids[0].SubjectRegExp,
		"https://github.com/nais/repo/.github/workflows/build.yml@refs/heads/main")
	assert.Regexp(t, ids[0].SubjectRegExp,
		"https://github.com/navikt/repo/.github/workflows/deploy.yaml@refs/pull/1/merge")

	// does not match other orgs
	assert.NotRegexp(t, ids[0].SubjectRegExp,
		"https://github.com/evilorg/repo/.github/workflows/build.yml@refs/heads/main")
}

func TestCertificateIdentity_GetIdentities_RegexMatchesExpectedSamples(t *testing.T) {
	type tc struct {
		name        string
		serverURL   string
		orgs        []string
		workFlowRef string
		fails       bool
	}

	tests := []tc{
		{
			name:        "matches git ref",
			serverURL:   "https://github.com",
			orgs:        []string{"nais"},
			workFlowRef: "nais/yolo-bolo/.github/workflows/.main.yml@refs/heads/master",
		},
		{
			name:        "matches encoded workflow name",
			serverURL:   "https://github.com",
			orgs:        []string{"nais"},
			workFlowRef: "nais/sapo/.github/workflows/PROD%20deploy.yml@refs/heads/sapo-upgrade",
		},
		{
			name:        "matches pull request ref",
			serverURL:   "https://github.com",
			orgs:        []string{"navikt"},
			workFlowRef: "navikt/yolo-bolo/.github/workflows/.build.yaml@refs/pull/1575/merge",
		},
		{
			name:        "matches tag ref",
			serverURL:   "https://github.com",
			orgs:        []string{"tull"},
			workFlowRef: "tull/yolo-bolo/.github/workflows/.build.yaml@refs/tags/1575/merge",
		},
		{
			name:        "fails different org",
			serverURL:   "https://github.com",
			orgs:        []string{"tull"},
			workFlowRef: "evilorg/yolo-bolo/.github/workflows/.build.yaml@refs/ta/1575/merge",
			fails:       true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			id := NewCertificateIdentity(tt.orgs)
			ids := id.GetIdentities()
			require.Len(t, ids, 1)

			full := tt.serverURL + "/" + tt.workFlowRef
			assert.Equal(t, IssuerUrl, ids[0].Issuer)

			if tt.fails {
				assert.NotRegexp(t, ids[0].SubjectRegExp, full)
			} else {
				assert.Regexp(t, ids[0].SubjectRegExp, full)
			}
		})
	}
}
