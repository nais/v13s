package attestation

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"strings"
	"testing"

	"github.com/nais/v13s/internal/attestation/github"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/stretchr/testify/require"
)

const googleIssuer = "https://accounts.google.com"

func TestCertificateIdentities(t *testing.T) {
	identities, err := certificateIdentities([]string{"nais", "navikt"}, googleIssuer, []string{" NAV.NO ", "example.org"})
	require.NoError(t, err)
	require.Len(t, identities, 2)

	for _, tt := range []struct {
		name    string
		issuer  string
		subject string
		allowed bool
	}{
		{"allowed email", googleIssuer, "signer@nav.no", true},
		{"other configured domain", googleIssuer, "signer@example.org", true},
		{"uppercase local part", googleIssuer, "Signer@nav.no", true},
		{"plus address", googleIssuer, "some.signer+build@nav.no", true},
		{"wrong issuer", "https://issuer.example.com", "signer@nav.no", false},
		{"issuer trailing slash", googleIssuer + "/", "signer@nav.no", false},
		{"issuer uppercase host", "https://ACCOUNTS.google.com", "signer@nav.no", false},
		{"GitHub issuer with email", github.IssuerUrl, "signer@nav.no", false},
		{"subdomain", googleIssuer, "signer@sub.nav.no", false},
		{"domain suffix", googleIssuer, "signer@nav.no.example.com", false},
		{"domain prefix", googleIssuer, "signer@evil-nav.no", false},
		{"unescaped dot", googleIssuer, "signer@navXno", false},
		{"second domain suffix", googleIssuer, "signer@example.org.evil.com", false},
		{"second domain prefix", googleIssuer, "signer@evil-example.org", false},
		{"second domain unescaped dot", googleIssuer, "signer@exampleXorg", false},
		{"second domain missing local part", googleIssuer, "@example.org", false},
		{"second domain wrong issuer", github.IssuerUrl, "signer@example.org", false},
		{"uppercase domain", googleIssuer, "signer@NAV.NO", false},
		{"newline", googleIssuer, "signer@nav.no\n", false},
		{"multiple at signs", googleIssuer, "signer@other@nav.no", false},
		{"missing local part", googleIssuer, "@nav.no", false},
		{"whitespace in local part", googleIssuer, "some signer@nav.no", false},
		{"newline in local part", googleIssuer, "signer\n@nav.no", false},
		{"URI instead of email", googleIssuer, "https://signer@nav.no", false},
		{"mailto URI instead of email", googleIssuer, "mailto:signer@nav.no", false},
		{"GitHub workflow", github.IssuerUrl, "https://github.com/navikt/repo/.github/workflows/build.yml@refs/heads/main", true},
		{"GitHub workflow with Google issuer", googleIssuer, "https://github.com/navikt/repo/.github/workflows/build.yml@refs/heads/main", false},
		{"unconfigured GitHub organization", github.IssuerUrl, "https://github.com/other/repo/.github/workflows/build.yml@refs/heads/main", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				Extensions: []pkix.Extension{{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
					Value: []byte(tt.issuer),
				}},
			}
			if strings.HasPrefix(tt.subject, "https://") || strings.HasPrefix(tt.subject, "mailto:") {
				subject, err := url.Parse(tt.subject)
				require.NoError(t, err)
				cert.URIs = []*url.URL{subject}
			} else {
				cert.EmailAddresses = []string{tt.subject}
			}
			err := cosign.CheckCertificatePolicy(cert, &cosign.CheckOpts{Identities: identities})
			if tt.allowed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestCertificateIdentitiesWithoutEmailDomains(t *testing.T) {
	organizations := []string{"nais", "navikt"}
	for _, issuer := range []string{"", "invalid", github.IssuerUrl} {
		t.Run(issuer, func(t *testing.T) {
			identities, err := certificateIdentities(organizations, issuer, nil)
			require.NoError(t, err)
			require.Equal(t, github.NewCertificateIdentity(organizations).GetIdentities(), identities)
		})
	}
}

func TestCertificateIdentitiesWithoutGitHubOrganizations(t *testing.T) {
	for _, domain := range []string{
		"nav.no", "a.b", "tenant-example.org", strings.Repeat("a", 63) + ".no",
		strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61),
	} {
		t.Run(domain, func(t *testing.T) {
			identities, err := certificateIdentities(nil, googleIssuer, []string{domain})
			require.NoError(t, err)
			require.Len(t, identities, 1)
			require.Equal(t, googleIssuer, identities[0].Issuer)
			require.Regexp(t, identities[0].SubjectRegExp, "signer@"+domain)
		})
	}
}

func TestCertificateIdentitiesCustomIssuer(t *testing.T) {
	issuer := "https://login.example.org/tenant/"
	identities, err := certificateIdentities(nil, " "+issuer+" ", []string{"nav.no", "example.org"})
	require.NoError(t, err)
	require.Len(t, identities, 1)

	for _, tt := range []struct {
		issuer  string
		email   string
		allowed bool
	}{
		{issuer, "signer@nav.no", true},
		{issuer, "signer@example.org", true},
		{issuer, "signer@other.org", false},
		{googleIssuer, "signer@nav.no", false},
		{strings.TrimSuffix(issuer, "/"), "signer@nav.no", false},
		{strings.ToUpper(issuer), "signer@nav.no", false},
	} {
		t.Run(tt.issuer+"/"+tt.email, func(t *testing.T) {
			cert := &x509.Certificate{
				EmailAddresses: []string{tt.email},
				Extensions: []pkix.Extension{{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
					Value: []byte(tt.issuer),
				}},
			}
			err := cosign.CheckCertificatePolicy(cert, &cosign.CheckOpts{Identities: identities})
			if tt.allowed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestNewVerifierRejectsInvalidEmailIssuer(t *testing.T) {
	for _, issuer := range []string{
		"", " ", "not-a-url", "http://issuer.example.org", "https://",
		"https://issuer.example.org?query=value", "https://issuer.example.org?",
		"https://issuer.example.org#fragment", "https://issuer.example.org#",
		"https://user:password@issuer.example.org", github.IssuerUrl,
	} {
		t.Run(issuer, func(t *testing.T) {
			v, err := NewVerifierWithEmailIdentity(context.Background(), nil, []string{"nais"}, issuer, []string{"nav.no"})
			require.ErrorContains(t, err, "attestation email issuer")
			require.NotContains(t, err.Error(), "password")
			require.Nil(t, v)
		})
	}
}

func TestNewVerifierRejectsInvalidIdentities(t *testing.T) {
	for _, domain := range []string{
		"", " ", "*", "@nav.no", "signer@nav.no", ".nav.no", "nav.no.", "nav..no",
		"nav", "nav .no", "-nav.no", "nav-.no", "nav.-no", "nav.no-", "nav.no|example.org", "nav\\.no",
		strings.Repeat("a", 64) + ".no",
		strings.Repeat(strings.Repeat("a", 63)+".", 4) + "no",
	} {
		t.Run(domain, func(t *testing.T) {
			v, err := NewVerifierWithEmailIdentity(context.Background(), nil, []string{"nais"}, googleIssuer, []string{"nav.no", domain})
			require.ErrorContains(t, err, "invalid attestation email domain")
			require.NotContains(t, err.Error(), "signer@nav.no")
			require.Nil(t, v)
		})
	}

	t.Run("no identities", func(t *testing.T) {
		v, err := NewVerifier(context.Background(), nil)
		require.ErrorContains(t, err, "at least one GitHub organization or attestation email domain")
		require.Nil(t, v)
	})
}
