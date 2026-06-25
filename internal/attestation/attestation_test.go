package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetAttestation_NoAttestation(t *testing.T) {
	v := &verifier{
		log:    logrus.NewEntry(logrus.New()),
		optsV3: &cosign.CheckOpts{NewBundleFormat: true},
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
	cert := createTestCertificate(t)

	v := &verifier{
		log:    logrus.NewEntry(logrus.New()),
		optsV3: &cosign.CheckOpts{NewBundleFormat: true},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			// return success regardless of v3/legacy in this unit test
			return []oci.Signature{&fakeSig{
				payload: dsse,
				cert:    cert,
				digest:  v1.Hash{Algorithm: "sha256", Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
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
	require.Equal(t, "push", a.Metadata["githubWorkflowTrigger"])
	require.Equal(t, "Build and deploy", a.Metadata["githubWorkflowName"])
	require.Equal(t, "nais/slsa-verde", a.Metadata["githubWorkflowRepository"])
	require.Equal(t, "refs/heads/main", a.Metadata["githubWorkflowRef"])
	require.Equal(t, "466d0132e9f57b984bf6e5a1cd0d6b00f675b882", a.Metadata["githubWorkflowSHA"])
	require.Equal(t, "https://github.com/nais/slsa-verde", a.Metadata["sourceRepositoryURI"])
	require.Equal(t, "https://github.com/nais/slsa-verde/.github/workflows/main.yml@refs/heads/main", a.Metadata["buildConfigURI"])
	require.Equal(t, "sha256:buildconfigdigest", a.Metadata["buildConfigDigest"])
	require.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", a.Metadata["imageDigest"])
	require.Equal(t, "github-hosted", a.Metadata["runnerEnvironment"])
}

func TestGetAttestation_MetadataFromChainWhenCertMissing(t *testing.T) {
	dsse := loadDSSEFromFile(t, "testdata/cyclonedx-dsse.json")
	cert := createTestCertificate(t)

	v := &verifier{
		log:    logrus.NewEntry(logrus.New()),
		optsV3: &cosign.CheckOpts{NewBundleFormat: true},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			return []oci.Signature{&fakeSig{
				payload: dsse,
				chain:   []*x509.Certificate{cert},
				digest:  v1.Hash{Algorithm: "sha256", Hex: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
			}}, nil
		},
	}

	a, err := v.GetAttestation(context.Background(), "example.com/test/image:tag")
	require.NoError(t, err)
	require.NotNil(t, a)
	require.NotEmpty(t, a.Metadata)
	require.Equal(t, "https://token.actions.githubusercontent.com", a.Metadata["oidcIssuer"])
	require.Equal(t, "Build and deploy", a.Metadata["githubWorkflowName"])
	require.Equal(t, "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", a.Metadata["imageDigest"])
}

func TestGetAttestation_PrefersNewBundlePath(t *testing.T) {
	legacyCalled := false
	v := &verifier{
		log:    logrus.NewEntry(logrus.New()),
		optsV3: &cosign.CheckOpts{NewBundleFormat: true},
		getBundles: func(ctx context.Context, signedImgRef name.Reference, registryClientOpts []cosignremote.Option, nameOpts ...name.Option) ([]*bundle.Bundle, *v1.Hash, error) {
			h := v1.Hash{Algorithm: "sha256", Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
			return []*bundle.Bundle{{}}, &h, nil
		},
		verifyNew: func(ctx context.Context, co *cosign.CheckOpts, artifactPolicyOption verify.ArtifactPolicyOption, entity verify.SignedEntity) (*verify.VerificationResult, error) {
			return makeCycloneDXVerificationResult("https://token.actions.githubusercontent.com", "https://github.com/nais/slsa-verde/.github/workflows/main.yml@refs/heads/main"), nil
		},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			legacyCalled = true
			return nil, nil
		},
	}

	a, err := v.GetAttestation(context.Background(), "example.com/test/image:tag")
	require.NoError(t, err)
	require.NotNil(t, a)
	require.NotNil(t, a.Predicate)
	require.False(t, legacyCalled, "legacy path should not run when new-bundle path succeeds")
	require.Equal(t, "https://token.actions.githubusercontent.com", a.Metadata["oidcIssuer"])
	require.Equal(t, "https://github.com/nais/slsa-verde/.github/workflows/main.yml@refs/heads/main", a.Metadata["subject"])
	require.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", a.Metadata["imageDigest"])
}

func TestGetAttestation_FallsBackToLegacyWhenNewBundleHasNoCycloneDX(t *testing.T) {
	dsse := loadDSSEFromFile(t, "testdata/cyclonedx-dsse.json")
	cert := createTestCertificate(t)
	legacyCalled := false

	v := &verifier{
		log:    logrus.NewEntry(logrus.New()),
		optsV3: &cosign.CheckOpts{NewBundleFormat: true},
		getBundles: func(ctx context.Context, signedImgRef name.Reference, registryClientOpts []cosignremote.Option, nameOpts ...name.Option) ([]*bundle.Bundle, *v1.Hash, error) {
			h := v1.Hash{Algorithm: "sha256", Hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
			return []*bundle.Bundle{{}}, &h, nil
		},
		verifyNew: func(ctx context.Context, co *cosign.CheckOpts, artifactPolicyOption verify.ArtifactPolicyOption, entity verify.SignedEntity) (*verify.VerificationResult, error) {
			return makeNonCycloneDXVerificationResult(), nil
		},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			legacyCalled = true
			return []oci.Signature{&fakeSig{payload: dsse, cert: cert, digest: v1.Hash{Algorithm: "sha256", Hex: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}}, nil
		},
	}

	a, err := v.GetAttestation(context.Background(), "example.com/test/image:tag")
	require.NoError(t, err)
	require.True(t, legacyCalled, "legacy path should be used when new-bundle path has no CycloneDX statement")
	require.Equal(t, "Build and deploy", a.Metadata["githubWorkflowName"])
	require.Equal(t, "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", a.Metadata["imageDigest"])
}

func TestGetAttestation_NewBundleWithoutMetadataStillSucceeds(t *testing.T) {
	v := &verifier{
		log:    logrus.NewEntry(logrus.New()),
		optsV3: &cosign.CheckOpts{NewBundleFormat: true},
		getBundles: func(ctx context.Context, signedImgRef name.Reference, registryClientOpts []cosignremote.Option, nameOpts ...name.Option) ([]*bundle.Bundle, *v1.Hash, error) {
			h := v1.Hash{Algorithm: "sha256", Hex: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
			return []*bundle.Bundle{{}}, &h, nil
		},
		verifyNew: func(ctx context.Context, co *cosign.CheckOpts, artifactPolicyOption verify.ArtifactPolicyOption, entity verify.SignedEntity) (*verify.VerificationResult, error) {
			return makeCycloneDXVerificationResult("", ""), nil
		},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			return nil, fmt.Errorf("legacy should not be called")
		},
	}

	a, err := v.GetAttestation(context.Background(), "example.com/test/image:tag")
	require.NoError(t, err)
	require.NotNil(t, a)
	require.NotNil(t, a.Predicate)
	require.Equal(t, map[string]string{
		"imageDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}, a.Metadata)
}

func TestResolveImageDigest_UsesDigestFromReferenceWithoutRegistryLookup(t *testing.T) {
	ref, err := name.ParseReference("example.com/test/image:v1@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	require.NoError(t, err)

	v := &verifier{
		log: logrus.NewEntry(logrus.New()),
		headFunc: func(ref name.Reference, options ...gcrremote.Option) (*v1.Descriptor, error) {
			t.Fatalf("headFunc should not be called when digest is already present in image reference")
			return nil, nil
		},
	}

	digest := v.resolveImageDigest(ref)
	require.Equal(t, "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", digest)
}

func TestResolveImageDigest_UsesRegistryLookupWhenReferenceHasNoDigest(t *testing.T) {
	ref, err := name.ParseReference("example.com/test/image:v1")
	require.NoError(t, err)

	v := &verifier{
		log: logrus.NewEntry(logrus.New()),
		headFunc: func(ref name.Reference, options ...gcrremote.Option) (*v1.Descriptor, error) {
			return &v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: "1111111111111111111111111111111111111111111111111111111111111111"}}, nil
		},
	}

	digest := v.resolveImageDigest(ref)
	require.Equal(t, "sha256:1111111111111111111111111111111111111111111111111111111111111111", digest)
}

func TestResolveImageDigest_ReturnsEmptyWhenRegistryLookupFails(t *testing.T) {
	ref, err := name.ParseReference("example.com/test/image:v1")
	require.NoError(t, err)

	v := &verifier{
		log: logrus.NewEntry(logrus.New()),
		headFunc: func(ref name.Reference, options ...gcrremote.Option) (*v1.Descriptor, error) {
			return nil, fmt.Errorf("head failed")
		},
	}

	digest := v.resolveImageDigest(ref)
	require.Empty(t, digest)
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

func TestAttestation_CompressAndDecompress(t *testing.T) {
	att := &Attestation{
		Metadata: map[string]string{
			"certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev",
		},
	}

	data, err := att.Compress()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	got, err := Decompress(data)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, att.Metadata["certificateIssuer"], got.Metadata["certificateIssuer"])
}

func TestAttestation_DecompressInvalidData(t *testing.T) {
	_, err := Decompress([]byte("not-gzip"))
	require.Error(t, err)
}

func loadDSSEFromFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

func createTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte("https://token.actions.githubusercontent.com")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}, Value: []byte("push")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, Value: []byte("466d0132e9f57b984bf6e5a1cd0d6b00f675b882")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}, Value: []byte("Build and deploy")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}, Value: []byte("nais/slsa-verde")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}, Value: []byte("refs/heads/main")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}, Value: []byte("github-hosted")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}, Value: []byte("https://github.com/nais/slsa-verde")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}, Value: []byte("https://github.com/nais/slsa-verde/.github/workflows/main.yml@refs/heads/main")},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 19}, Value: []byte("sha256:buildconfigdigest")},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func makeCycloneDXVerificationResult(issuer string, subject string) *verify.VerificationResult {
	predicate, err := structpb.NewStruct(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6"})
	if err != nil {
		panic(err)
	}
	result := &verify.VerificationResult{
		Statement: &attestationv1.Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: in_toto.PredicateCycloneDX,
			Predicate:     predicate,
		},
	}

	if issuer != "" || subject != "" {
		result.Signature = &verify.SignatureVerificationResult{
			Certificate: &fulciocert.Summary{
				CertificateIssuer:      issuer,
				SubjectAlternativeName: subject,
				Extensions: fulciocert.Extensions{
					Issuer:         issuer,
					BuildConfigURI: subject,
				},
			},
		}
	}

	return result
}

func makeNonCycloneDXVerificationResult() *verify.VerificationResult {
	predicate, err := structpb.NewStruct(map[string]any{"foo": "bar"})
	if err != nil {
		panic(err)
	}
	return &verify.VerificationResult{
		Statement: &attestationv1.Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://slsa.dev/provenance/v1",
			Predicate:     predicate,
		},
	}
}
