package github

import (
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"
)

const (
	IssuerUrl = "https://token.actions.githubusercontent.com"
)

type CertificateIdentity struct {
	logger        *log.Entry
	Organizations []string
}

func NewCertificateIdentity(organisations []string) *CertificateIdentity {
	return &CertificateIdentity{
		logger:        log.WithField("package", "github"),
		Organizations: organisations,
	}
}

func (c *CertificateIdentity) GetIdentities() []cosign.Identity {
	var ids []cosign.Identity
	for _, org := range c.Organizations {
		ids = append(ids, cosign.Identity{
			Issuer:        IssuerUrl,
			SubjectRegExp: "^https:\\/\\/github\\.com\\/" + org + "\\/[a-zA-Z0-9_.-]+?\\/.github\\/workflows\\/[a-zA-Z0-9_.-]+?(?:.yaml|.yml)@refs\\/(?:heads|pull|tags)[a-zA-Z0-9_\\/.-]+$",
		})
	}
	return ids
}
