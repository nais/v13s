package identity

import (
	"regexp"

	"github.com/sigstore/cosign/v2/pkg/cosign"
)

const (
	GitHubIssuerURL = "https://token.actions.githubusercontent.com"
)

func GitHubWorkflowIdentity(enabled bool) []cosign.Identity {
	if !enabled {
		return nil
	}

	re := regexp.MustCompile(
		`^https://github\.com/[^/]+/[^/]+/\.github/workflows/.+\.(ya?ml)@refs/(heads|pull|tags)/.+$`,
	)
	return []cosign.Identity{
		{
			Issuer:        GitHubIssuerURL,
			SubjectRegExp: re.String(),
		},
	}
}
