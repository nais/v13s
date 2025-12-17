package attestation

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"unicode"

	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/rekor/pkg/pki"
	dsse "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	intoto "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
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

type Rekor struct {
	OIDCIssuer               string `json:"oidcIssuer"`
	GitHubWorkflowName       string `json:"githubWorkflowName"`
	GitHubWorkflowRef        string `json:"githubWorkflowRef"`
	BuildTrigger             string `json:"buildTrigger"`
	RunInvocationURI         string `json:"runInvocationURI"`
	RunnerEnvironment        string `json:"runnerEnvironment"`
	SourceRepositoryOwnerURI string `json:"sourceRepositoryOwnerURI"`
	BuildConfigURI           string `json:"buildConfigURI"`
	IntegratedTime           string `json:"integratedTime"`
	LogIndex                 string `json:"logIndex"`
	GitHubWorkflowSHA        string `json:"githubWorkflowSHA"`
}

func GetRekorMetadata(rekorBundle *bundle.RekorBundle) (*Rekor, error) {
	decoded, err := base64.StdEncoding.DecodeString(rekorBundle.Payload.Body.(string))
	if err != nil {
		return nil, fmt.Errorf("failed to decode log entry: %w", err)
	}

	canonicalValue, err := logEntryToPubKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to get verifier: %w", err)
	}

	metadata, err := certToRekorMetadata(canonicalValue, rekorBundle.Payload.IntegratedTime, rekorBundle.Payload.LogIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get rekor metadata: %w", err)
	}

	return metadata, nil
}

func logEntryToPubKey(decodedAnon []byte) ([]byte, error) {
	logEntryPayload := struct {
		Spec json.RawMessage `json:"spec"`
		Kind string          `json:"kind"`
	}{}
	err := json.Unmarshal(decodedAnon, &logEntryPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal log entry payload: %w", err)
	}

	var verifiers []pki.PublicKey
	switch logEntryPayload.Kind {
	case "dsse":
		dsseData := dsse.V001Entry{}
		err = json.Unmarshal(logEntryPayload.Spec, &dsseData.DSSEObj)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal intoto data: %w", err)
		}

		verifiers, err = dsseData.Verifiers()
		if err != nil {
			return nil, fmt.Errorf("failed to get verifiers: %w", err)
		}
	case "intoto":
		intotoData := intoto.V001Entry{}
		err = json.Unmarshal(logEntryPayload.Spec, &intotoData.IntotoObj)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal intoto data: %w", err)
		}

		verifiers, err = intotoData.Verifiers()
		if err != nil {
			return nil, fmt.Errorf("failed to get verifiers: %w", err)
		}
	default:
		return nil, fmt.Errorf("verifiers not found")
	}

	canonicalValue, err := getCanonicalValue(verifiers)
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical value: %w", err)
	}

	if canonicalValue == nil {
		return nil, fmt.Errorf("canonical value not found")
	}

	return canonicalValue, nil
}

func getCanonicalValue(verifiers []pki.PublicKey) ([]byte, error) {
	for _, verifier := range verifiers {
		canon, err := verifier.CanonicalValue()
		if err != nil {
			return nil, err
		}
		if canon != nil {
			return canon, nil
		}
	}
	return nil, fmt.Errorf("verifier not found")
}

func certToRekorMetadata(canonicalValue []byte, integratedTime int64, logIndex int64) (*Rekor, error) {
	rekorMetadata := &Rekor{}
	for block, rest := pem.Decode(canonicalValue); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}

			for _, ext := range cert.Extensions {
				switch ext.Id.String() {
				case OIDCIssuer.String():
					rekorMetadata.OIDCIssuer = string(ext.Value)
				case GithubWorkflowSHA.String():
					rekorMetadata.GitHubWorkflowSHA = string(ext.Value)
				case GithubWorkflowName.String():
					rekorMetadata.GitHubWorkflowName = string(ext.Value)
				case GithubWorkflowRef.String():
					rekorMetadata.GitHubWorkflowRef = string(ext.Value)
				case BuildTrigger.String():
					rekorMetadata.BuildTrigger = removeNoneGraphicChars(string(ext.Value))
				case RunInvocationURI.String():
					rekorMetadata.RunInvocationURI = trimBeforeSubstring(string(ext.Value), "https://")
				case RunnerEnvironment.String():
					rekorMetadata.RunnerEnvironment = removeNoneGraphicChars(string(ext.Value))
				case SourceRepositoryOwnerURI.String():
					rekorMetadata.SourceRepositoryOwnerURI = removeNoneGraphicChars(string(ext.Value))
				case BuildConfigURI.String():
					rekorMetadata.BuildConfigURI = trimBeforeSubstring(string(ext.Value), "https://")
				}
			}
			rekorMetadata.LogIndex = fmt.Sprintf("%d", logIndex)
			rekorMetadata.IntegratedTime = fmt.Sprintf("%d", integratedTime)
		}
	}
	return rekorMetadata, nil
}

func removeNoneGraphicChars(s string) string {
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
