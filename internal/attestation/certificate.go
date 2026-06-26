package attestation

import (
	"crypto/x509"
	"strings"
	"unicode"

	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

type ExtensionIdentifier string

const (
	OIDCIssuer                          ExtensionIdentifier = "1.3.6.1.4.1.57264.1.1"
	GithubWorkflowTrigger               ExtensionIdentifier = "1.3.6.1.4.1.57264.1.2"
	GithubWorkflowSHA                   ExtensionIdentifier = "1.3.6.1.4.1.57264.1.3"
	GithubWorkflowName                  ExtensionIdentifier = "1.3.6.1.4.1.57264.1.4"
	GithubWorkflowRepository            ExtensionIdentifier = "1.3.6.1.4.1.57264.1.5"
	GithubWorkflowRef                   ExtensionIdentifier = "1.3.6.1.4.1.57264.1.6"
	BuildSignerURI                      ExtensionIdentifier = "1.3.6.1.4.1.57264.1.9"
	BuildSignerDigest                   ExtensionIdentifier = "1.3.6.1.4.1.57264.1.10"
	RunnerEnvironment                   ExtensionIdentifier = "1.3.6.1.4.1.57264.1.11"
	SourceRepositoryURI                 ExtensionIdentifier = "1.3.6.1.4.1.57264.1.12"
	SourceRepositoryDigest              ExtensionIdentifier = "1.3.6.1.4.1.57264.1.13"
	SourceRepositoryRef                 ExtensionIdentifier = "1.3.6.1.4.1.57264.1.14"
	SourceRepositoryIdentifier          ExtensionIdentifier = "1.3.6.1.4.1.57264.1.15"
	SourceRepositoryOwnerURI            ExtensionIdentifier = "1.3.6.1.4.1.57264.1.16"
	SourceRepositoryOwnerIdentifier     ExtensionIdentifier = "1.3.6.1.4.1.57264.1.17"
	BuildConfigURI                      ExtensionIdentifier = "1.3.6.1.4.1.57264.1.18"
	BuildConfigDigest                   ExtensionIdentifier = "1.3.6.1.4.1.57264.1.19"
	BuildTrigger                        ExtensionIdentifier = "1.3.6.1.4.1.57264.1.20"
	RunInvocationURI                    ExtensionIdentifier = "1.3.6.1.4.1.57264.1.21"
	SourceRepositoryVisibilityAtSigning ExtensionIdentifier = "1.3.6.1.4.1.57264.1.22"
)

func (e ExtensionIdentifier) String() string {
	return string(e)
}

type CertificateMetadata struct {
	CertificateIssuer        string `json:"certificateIssuer"`
	Subject                  string `json:"subject"`
	OIDCIssuer               string `json:"oidcIssuer"`
	GitHubWorkflowTrigger    string `json:"githubWorkflowTrigger"`
	GitHubWorkflowName       string `json:"githubWorkflowName"`
	GitHubWorkflowRef        string `json:"githubWorkflowRef"`
	GitHubWorkflowRepository string `json:"githubWorkflowRepository"`
	BuildTrigger             string `json:"buildTrigger"`
	RunInvocationURI         string `json:"runInvocationURI"`
	RunnerEnvironment        string `json:"runnerEnvironment"`
	SourceRepositoryURI      string `json:"sourceRepositoryURI"`
	SourceRepositoryOwnerURI string `json:"sourceRepositoryOwnerURI"`
	BuildConfigURI           string `json:"buildConfigURI"`
	BuildConfigDigest        string `json:"buildConfigDigest"`
	GitHubWorkflowSHA        string `json:"githubWorkflowSHA"`
}

type certificateMetadataInput struct {
	certificateIssuer        string
	subject                  string
	oidcIssuer               string
	githubWorkflowTrigger    string
	githubWorkflowName       string
	githubWorkflowRef        string
	githubWorkflowRepository string
	buildTrigger             string
	runInvocationURI         string
	runnerEnvironment        string
	sourceRepositoryURI      string
	sourceRepositoryOwnerURI string
	buildConfigURI           string
	buildConfigDigest        string
	githubWorkflowSHA        string
}

func GetCertificateMetadata(cert *x509.Certificate) *CertificateMetadata {
	if cert == nil {
		return &CertificateMetadata{}
	}

	input := certificateMetadataInput{
		certificateIssuer: cert.Issuer.String(),
	}

	for _, ext := range cert.Extensions {
		switch ext.Id.String() {
		case OIDCIssuer.String():
			input.oidcIssuer = string(ext.Value)
		case GithubWorkflowTrigger.String():
			input.githubWorkflowTrigger = string(ext.Value)
		case GithubWorkflowSHA.String():
			input.githubWorkflowSHA = string(ext.Value)
		case GithubWorkflowName.String():
			input.githubWorkflowName = string(ext.Value)
		case GithubWorkflowRepository.String():
			input.githubWorkflowRepository = string(ext.Value)
		case GithubWorkflowRef.String():
			input.githubWorkflowRef = string(ext.Value)
		case BuildTrigger.String():
			input.buildTrigger = string(ext.Value)
		case RunInvocationURI.String():
			input.runInvocationURI = string(ext.Value)
		case RunnerEnvironment.String():
			input.runnerEnvironment = string(ext.Value)
		case SourceRepositoryURI.String():
			input.sourceRepositoryURI = string(ext.Value)
		case SourceRepositoryOwnerURI.String():
			input.sourceRepositoryOwnerURI = string(ext.Value)
		case BuildConfigURI.String():
			input.buildConfigURI = string(ext.Value)
		case BuildConfigDigest.String():
			input.buildConfigDigest = string(ext.Value)
		}
	}

	if len(cert.URIs) > 0 {
		input.subject = cert.URIs[0].String()
	}

	return buildCertificateMetadata(input)
}

func GetCertificateMetadataFromSummary(summary *fulciocert.Summary) *CertificateMetadata {
	if summary == nil {
		return &CertificateMetadata{}
	}

	return buildCertificateMetadata(certificateMetadataInput{
		certificateIssuer:        summary.CertificateIssuer,
		subject:                  summary.SubjectAlternativeName,
		oidcIssuer:               summary.Extensions.Issuer,
		githubWorkflowTrigger:    summary.Extensions.GithubWorkflowTrigger,
		githubWorkflowSHA:        summary.Extensions.GithubWorkflowSHA,
		githubWorkflowName:       summary.Extensions.GithubWorkflowName,
		githubWorkflowRepository: summary.Extensions.GithubWorkflowRepository,
		githubWorkflowRef:        summary.Extensions.GithubWorkflowRef,
		buildTrigger:             summary.Extensions.BuildTrigger,
		runInvocationURI:         summary.Extensions.RunInvocationURI,
		runnerEnvironment:        summary.Extensions.RunnerEnvironment,
		sourceRepositoryURI:      summary.Extensions.SourceRepositoryURI,
		sourceRepositoryOwnerURI: summary.Extensions.SourceRepositoryOwnerURI,
		buildConfigURI:           summary.Extensions.BuildConfigURI,
		buildConfigDigest:        summary.Extensions.BuildConfigDigest,
	})
}

func buildCertificateMetadata(input certificateMetadataInput) *CertificateMetadata {
	metadata := &CertificateMetadata{
		CertificateIssuer:        removeNonGraphicChars(input.certificateIssuer),
		Subject:                  removeNonGraphicChars(input.subject),
		OIDCIssuer:               removeNonGraphicChars(input.oidcIssuer),
		GitHubWorkflowTrigger:    removeNonGraphicChars(input.githubWorkflowTrigger),
		GitHubWorkflowName:       removeNonGraphicChars(input.githubWorkflowName),
		GitHubWorkflowRef:        removeNonGraphicChars(input.githubWorkflowRef),
		GitHubWorkflowRepository: removeNonGraphicChars(input.githubWorkflowRepository),
		BuildTrigger:             removeNonGraphicChars(input.buildTrigger),
		RunInvocationURI:         trimBeforeSubstring(removeNonGraphicChars(input.runInvocationURI), "https://"),
		RunnerEnvironment:        removeNonGraphicChars(input.runnerEnvironment),
		SourceRepositoryURI:      trimBeforeSubstring(removeNonGraphicChars(input.sourceRepositoryURI), "https://"),
		SourceRepositoryOwnerURI: trimBeforeSubstring(removeNonGraphicChars(input.sourceRepositoryOwnerURI), "https://"),
		BuildConfigURI:           trimBeforeSubstring(removeNonGraphicChars(input.buildConfigURI), "https://"),
		BuildConfigDigest:        removeNonGraphicChars(input.buildConfigDigest),
		GitHubWorkflowSHA:        removeNonGraphicChars(input.githubWorkflowSHA),
	}

	return metadata
}

func removeNonGraphicChars(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, s)
}

func trimBeforeSubstring(input, substring string) string {
	index := strings.Index(input, substring)
	if index == -1 {
		return input
	}
	return input[index:]
}
