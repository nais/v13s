package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestGetAttestation_NoAttestation(t *testing.T) {
	v := &verifier{
		log:  logrus.NewEntry(logrus.New()),
		opts: &cosign.CheckOpts{}, // doesn't need to be real for this test
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			return nil, fmt.Errorf("no matching attestations")
		},
	}

	_, err := v.GetAttestation(context.Background(), "example.com/test/image:tag")
	require.Error(t, err)
	require.Contains(t, err.Error(), ErrNoAttestation)
}

func TestGetAttestation_Success(t *testing.T) {
	dsse := loadDSSEFromFile(t, "testdata/cyclonedx-dsse.json")
	st, err := ParseEnvelope(dsse)
	require.NoError(t, err)
	rBundle := loadRekorBundleFromFile(t, "testdata/rekor-bundle.json")

	v := &verifier{
		log:  logrus.NewEntry(logrus.New()),
		opts: &cosign.CheckOpts{},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			return []oci.Signature{&fakeSig{
				payload: dsse,
				bundle:  rBundle,
			}}, nil
		},
	}

	a, err := v.GetAttestation(context.Background(), "example.com/test/image:tag")
	require.NoError(t, err)
	require.NotNil(t, a)
	require.NotNil(t, a.Predicate)
	require.Equal(t, in_toto.PredicateCycloneDX, st.PredicateType)

	require.NotEmpty(t, a.Metadata, "metadata should not be empty")

	require.Equal(t, "https://token.actions.githubusercontent.com", a.Metadata["oidcIssuer"])
	require.Equal(t, "Build and deploy", a.Metadata["githubWorkflowName"])
	require.Equal(t, "refs/heads/main", a.Metadata["githubWorkflowRef"])
	require.Equal(t, "https://github.com/nais/slsa-verde/.github/workflows/main.yml@refs/heads/main", a.Metadata["buildConfigURI"])
	require.Equal(t, "github-hosted", a.Metadata["runnerEnvironment"])
	require.Equal(t, "180735265", a.Metadata["logIndex"])
	require.Equal(t, "1741769683", a.Metadata["integratedTime"])
}

func TestDSSEParsePayload(t *testing.T) {
	dsse := loadDSSEFromFile(t, "testdata/cyclonedx-dsse.json")
	got, err := ParseEnvelope(dsse)
	assert.NoError(t, err)

	att, err := os.ReadFile("testdata/cyclonedx-attestation.json")
	assert.NoError(t, err)

	var want *in_toto.CycloneDXStatement
	err = json.Unmarshal(att, &want)
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func loadRekorBundleFromFile(t *testing.T, s string) *bundle.RekorBundle {
	t.Helper()
	b, err := os.ReadFile(s)
	require.NoError(t, err)

	var rBundle bundle.RekorBundle
	err = json.Unmarshal(b, &rBundle)
	require.NoError(t, err)
	return &rBundle
}

func loadDSSEFromFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}
