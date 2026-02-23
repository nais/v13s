package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAttestation_NoAttestation(t *testing.T) {
	v := &verifier{
		log:        logrus.NewEntry(logrus.New()),
		optsV3:     &cosign.CheckOpts{NewBundleFormat: true},
		optsLegacy: &cosign.CheckOpts{NewBundleFormat: false},
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
		log:        logrus.NewEntry(logrus.New()),
		optsV3:     &cosign.CheckOpts{NewBundleFormat: true},
		optsLegacy: &cosign.CheckOpts{NewBundleFormat: false},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			// return success regardless of v3/legacy in this unit test
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

func TestGetAttestation_TriesBundleThenFallsBack(t *testing.T) {
	dsse := loadDSSEFromFile(t, "testdata/cyclonedx-dsse.json")
	rBundle := loadRekorBundleFromFile(t, "testdata/rekor-bundle.json")

	var sawV3, sawLegacy bool

	v := &verifier{
		log:        logrus.NewEntry(logrus.New()),
		optsV3:     &cosign.CheckOpts{NewBundleFormat: true},
		optsLegacy: &cosign.CheckOpts{NewBundleFormat: false},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			if co.NewBundleFormat {
				sawV3 = true
				// Simulate: no bundles found in registry
				return nil, fmt.Errorf("no valid bundles exist in registry")
			}
			sawLegacy = true
			// Legacy succeeds
			return []oci.Signature{&fakeSig{payload: dsse, bundle: rBundle}}, nil
		},
	}

	att, err := v.GetAttestation(context.Background(), "example.com/test/image:tag")
	require.NoError(t, err)
	require.NotNil(t, att)
	require.True(t, sawV3, "should try v3 bundle path first")
	require.True(t, sawLegacy, "should fall back to legacy after v3 fails")
}

func TestGetAttestation_4xxPreventsFallback(t *testing.T) {
	var legacyCalled bool

	v := &verifier{
		log:        logrus.NewEntry(logrus.New()),
		optsV3:     &cosign.CheckOpts{NewBundleFormat: true},
		optsLegacy: &cosign.CheckOpts{NewBundleFormat: false},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			if co.NewBundleFormat {
				// Simulate v3 returning a 4xx error
				return nil, &fakeTransportError{statusCode: 404}
			}
			legacyCalled = true
			return nil, fmt.Errorf("should not be called")
		},
	}

	_, err := v.GetAttestation(context.Background(), "example.com/test/image:tag")
	require.Error(t, err)
	assert.False(t, legacyCalled, "legacy fallback should not be triggered on 4xx error")
}

// fakeTransportError simulates a transport.Error with a given status code
// for testing fallback prevention logic.
type fakeTransportError struct {
	statusCode int
}

func (e *fakeTransportError) Error() string {
	return fmt.Sprintf("fake transport error %d", e.statusCode)
}
func (e *fakeTransportError) StatusCode() int { return e.statusCode }

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

func TestAttestation_CompressAndDecompress(t *testing.T) {
	att := &Attestation{
		Metadata: map[string]string{
			"issuer": "https://token.actions.githubusercontent.com",
		},
	}

	data, err := att.Compress()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	got, err := Decompress(data)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, att.Metadata["issuer"], got.Metadata["issuer"])
}

func TestAttestation_DecompressInvalidData(t *testing.T) {
	_, err := Decompress([]byte("not-gzip"))
	require.Error(t, err)
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
