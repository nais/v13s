package github

import (
	"regexp"
	"strings"

	"github.com/sigstore/cosign/v3/pkg/cosign"
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
	if len(c.Organizations) == 0 {
		return nil
	}

	escapedOrgs := make([]string, len(c.Organizations))
	for i, org := range c.Organizations {
		escapedOrgs[i] = regexp.QuoteMeta(org)
	}
	orgs := strings.Join(escapedOrgs, "|")
	subject := "^https:\\/\\/github\\.com\\/(" + orgs + ")\\/[a-zA-Z0-9_.-]+?\\/.github\\/workflows\\/.+?(?:\\.yaml|\\.yml).*$"

	return []cosign.Identity{
		{Issuer: IssuerUrl, SubjectRegExp: subject},
	}
}
