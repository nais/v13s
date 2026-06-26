package attestation

import (
	"testing"

	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/stretchr/testify/require"
)

func TestGetCertificateMetadataFromSummary(t *testing.T) {
	summary := &fulciocert.Summary{
		CertificateIssuer:      "https://token.actions.githubusercontent.com",
		SubjectAlternativeName: "https://github.com/nais/slsa-verde/.github/workflows/main.yml@refs/heads/main",
		Extensions: fulciocert.Extensions{
			Issuer:                   "https://token.actions.githubusercontent.com",
			GithubWorkflowTrigger:    "push",
			GithubWorkflowSHA:        "466d0132e9f57b984bf6e5a1cd0d6b00f675b882",
			GithubWorkflowName:       "Build and deploy",
			GithubWorkflowRepository: "nais/slsa-verde",
			GithubWorkflowRef:        "refs/heads/main",
			RunnerEnvironment:        "github-hosted",
			SourceRepositoryURI:      "https://github.com/nais/slsa-verde",
			SourceRepositoryOwnerURI: "https://github.com/nais",
			BuildConfigURI:           "https://github.com/nais/slsa-verde/.github/workflows/main.yml@refs/heads/main",
			BuildConfigDigest:        "sha256:buildconfigdigest",
			BuildTrigger:             "push",
			RunInvocationURI:         "prefix https://github.com/nais/slsa-verde/actions/runs/123",
		},
	}

	metadata := GetCertificateMetadataFromSummary(summary)
	require.Equal(t, "https://token.actions.githubusercontent.com", metadata.CertificateIssuer)
	require.Equal(t, "https://token.actions.githubusercontent.com", metadata.OIDCIssuer)
	require.Equal(t, "https://github.com/nais/slsa-verde/.github/workflows/main.yml@refs/heads/main", metadata.Subject)
	require.Equal(t, "push", metadata.GitHubWorkflowTrigger)
	require.Equal(t, "Build and deploy", metadata.GitHubWorkflowName)
	require.Equal(t, "nais/slsa-verde", metadata.GitHubWorkflowRepository)
	require.Equal(t, "refs/heads/main", metadata.GitHubWorkflowRef)
	require.Equal(t, "466d0132e9f57b984bf6e5a1cd0d6b00f675b882", metadata.GitHubWorkflowSHA)
	require.Equal(t, "github-hosted", metadata.RunnerEnvironment)
	require.Equal(t, "https://github.com/nais/slsa-verde", metadata.SourceRepositoryURI)
	require.Equal(t, "https://github.com/nais", metadata.SourceRepositoryOwnerURI)
	require.Equal(t, "https://github.com/nais/slsa-verde/.github/workflows/main.yml@refs/heads/main", metadata.BuildConfigURI)
	require.Equal(t, "sha256:buildconfigdigest", metadata.BuildConfigDigest)
	require.Equal(t, "push", metadata.BuildTrigger)
	require.Equal(t, "https://github.com/nais/slsa-verde/actions/runs/123", metadata.RunInvocationURI)
}

func TestGetCertificateMetadataFromSummary_Fallbacks(t *testing.T) {
	summary := &fulciocert.Summary{
		CertificateIssuer: "CN=sigstore-intermediate,O=sigstore.dev",
		Extensions: fulciocert.Extensions{
			Issuer:         "https://issuer.example",
			BuildConfigURI: "https://github.com/navikt/workflow.yml@refs/heads/main",
		},
	}

	metadata := GetCertificateMetadataFromSummary(summary)
	require.Equal(t, "CN=sigstore-intermediate,O=sigstore.dev", metadata.CertificateIssuer)
	require.Equal(t, "https://issuer.example", metadata.OIDCIssuer)
	require.Empty(t, metadata.Subject)
}
