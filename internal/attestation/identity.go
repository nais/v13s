package attestation

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/nais/v13s/internal/attestation/github"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

var emailDomainPattern = regexp.MustCompile(`^[a-z0-9.-]+$`)

func validEmailDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") || !emailDomainPattern.MatchString(domain) {
		return false
	}
	for label := range strings.SplitSeq(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func certificateIdentities(organizations []string, emailIssuer string, allowedEmailDomains []string) ([]cosign.Identity, error) {
	identities := github.NewCertificateIdentity(organizations).GetIdentities()
	emailIssuer = strings.TrimSpace(emailIssuer)
	if len(allowedEmailDomains) > 0 {
		issuerURL, err := url.Parse(emailIssuer)
		if err != nil || issuerURL.Scheme != "https" || issuerURL.Hostname() == "" || issuerURL.User != nil ||
			issuerURL.RawQuery != "" || issuerURL.ForceQuery || strings.Contains(emailIssuer, "#") || emailIssuer == github.IssuerUrl {
			return nil, fmt.Errorf("attestation email issuer must be an HTTPS URL for an email identity provider, without credentials, query or fragment")
		}
	}
	domains := make([]string, len(allowedEmailDomains))
	for i, domain := range allowedEmailDomains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if !validEmailDomain(domain) {
			return nil, fmt.Errorf("invalid attestation email domain at index %d", i)
		}
		domains[i] = regexp.QuoteMeta(domain)
	}
	if len(domains) > 0 {
		identities = append(identities, cosign.Identity{
			Issuer:        emailIssuer,
			SubjectRegExp: `^[^@\s:]+@(` + strings.Join(domains, "|") + `)$`,
		})
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("at least one GitHub organization or attestation email domain must be configured")
	}
	return identities, nil
}
