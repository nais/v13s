package identity

import (
	"testing"

	"github.com/nais/v13s/internal/config"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetIdentities(t *testing.T) {
	const validRegex = `^https://github\.com/[^/]+/[^/]+/\.github/workflows/.+\.(ya?ml)@refs/(heads|pull|tags)/.+$`
	log := logrus.New().WithField("test", true)

	testCases := []struct {
		name        string
		cfg         config.IdentityEnforcementConfig
		expectCount int
		expect      []cosign.Identity
	}{
		{
			name: "disabled identity enforcement returns nil",
			cfg: config.IdentityEnforcementConfig{
				Enabled: false,
				Identities: []config.Identity{
					{Issuer: "issuer", Subject: validRegex},
				},
			},
			expectCount: 0,
			expect:      nil,
		},
		{
			name: "enabled but no identities configured",
			cfg: config.IdentityEnforcementConfig{
				Enabled:    true,
				Identities: nil,
			},
			expectCount: 0,
			expect:      []cosign.Identity{},
		},
		{
			name: "valid identity",
			cfg: config.IdentityEnforcementConfig{
				Enabled: true,
				Identities: []config.Identity{
					{
						Issuer:  "https://github.com",
						Subject: validRegex,
					},
				},
			},
			expectCount: 1,
			expect: []cosign.Identity{
				{
					Issuer:        "https://github.com",
					SubjectRegExp: validRegex,
				},
			},
		},
		{
			name: "invalid regex is skipped",
			cfg: config.IdentityEnforcementConfig{
				Enabled: true,
				Identities: []config.Identity{
					{
						Issuer:  "https://github.com",
						Subject: "(",
					},
				},
			},
			expectCount: 0,
			expect:      []cosign.Identity{},
		},
		{
			name: "multiple identities, only valid ones kept",
			cfg: config.IdentityEnforcementConfig{
				Enabled: true,
				Identities: []config.Identity{
					{Issuer: "https://github.com", Subject: "("},        // invalid
					{Issuer: "https://github.com", Subject: validRegex}, // valid
				},
			},
			expectCount: 1,
			expect: []cosign.Identity{
				{
					Issuer:        "https://github.com",
					SubjectRegExp: validRegex,
				},
			},
		},
		{
			name: "all invalid identities returns empty slice but not nil",
			cfg: config.IdentityEnforcementConfig{
				Enabled: true,
				Identities: []config.Identity{
					{Issuer: "https://github.com", Subject: "("},
					{Issuer: "https://example.com", Subject: "["},
				},
			},
			expectCount: 0,
			expect:      []cosign.Identity{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ids := GetIdentities(tc.cfg, log)

			if !tc.cfg.Enabled {
				assert.Nil(t, ids, "disabled mode should return nil")
				return
			}

			assert.Len(t, ids, tc.expectCount)
			assert.Equal(t, tc.expect, ids)
		})
	}
}
