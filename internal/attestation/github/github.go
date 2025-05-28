package github

import (
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

const (
	IssuerUrl = "https://token.actions.githubusercontent.com"
)

type CertificateIdentity struct {
	Organizations []string
}

func NewCertificateIdentity(organisations []string) *CertificateIdentity {
	return &CertificateIdentity{
		Organizations: organisations,
	}
}

func (c *CertificateIdentity) GetIdentities() []cosign.Identity {
	var ids []cosign.Identity
	for _, org := range c.Organizations {
		ids = append(ids, cosign.Identity{
			Issuer:        IssuerUrl,
			SubjectRegExp: "^https:\\/\\/github\\.com\\/" + org + "\\/[a-zA-Z0-9_.-]+?\\/.github\\/workflows\\/.+?(?:.yaml|.yml).*$",
		})
	}
	return ids
}
