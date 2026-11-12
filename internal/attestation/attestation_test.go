package attestation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ociremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAttestation_RegistryRequestsRespectCancellation(t *testing.T) {
	for _, format := range []string{"v3", "legacy"} {
		t.Run(format, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/v2/" {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("")),
						Request:    req,
					}, nil
				}
				cancel()
				assert.ErrorIs(t, req.Context().Err(), context.Canceled)
				return nil, context.Canceled
			})
			v := &verifier{
				log: logrus.NewEntry(logrus.New()),
				optsV3: &cosign.CheckOpts{
					RootCerts: x509.NewCertPool(),
					RegistryClientOpts: []remote.Option{
						remote.WithRemoteOptions(
							ociremote.WithAuth(authn.Anonymous),
							ociremote.WithTransport(transport),
						),
					},
				},
				verifyFunc: func(ctx context.Context, ref name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, error) {
					if format == "legacy" && opts.NewBundleFormat {
						return nil, fmt.Errorf("no v3 attestations")
					}
					sigs, _, err := cosign.VerifyImageAttestations(ctx, ref, opts)
					return sigs, err
				},
			}

			_, err := v.GetAttestation(ctx, "registry.invalid/test/image:tag")
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

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

func TestVerifyBundleFormatPreservesIdentities(t *testing.T) {
	identities, err := certificateIdentities([]string{"nais"}, "https://issuer.example.org", []string{"nav.no"})
	require.NoError(t, err)

	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			calls := 0
			v := &verifier{
				log:    logrus.NewEntry(logrus.New()),
				optsV3: &cosign.CheckOpts{Identities: identities, NewBundleFormat: true},
				verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
					calls++
					require.False(t, co.IgnoreTlog)
					require.False(t, co.IgnoreSCT)
					if co.NewBundleFormat {
						require.Equal(t, []cosign.Identity{identities[calls-1]}, co.Identities)
						if legacy {
							return nil, &cosign.ErrNoMatchingAttestations{}
						}
					} else {
						require.True(t, legacy)
						require.Equal(t, identities, co.Identities)
					}
					return []oci.Signature{&fakeSig{}}, nil
				},
			}
			ref, err := name.ParseReference("example.com/test/image:tag")
			require.NoError(t, err)
			sigs, err := v.verifyBundleFormat(context.Background(), ref)
			require.NoError(t, err)
			if legacy {
				require.Len(t, sigs, 1)
				require.Equal(t, 3, calls)
			} else {
				require.Len(t, sigs, 2)
				require.Equal(t, 2, calls)
			}
			require.True(t, v.optsV3.NewBundleFormat)
			require.Equal(t, identities, v.optsV3.Identities)
		})
	}
}

func TestVerifyBundleFormatAcceptsAnyV3Identity(t *testing.T) {
	identities, err := certificateIdentities([]string{"nais"}, "https://issuer.example.org", []string{"nav.no"})
	require.NoError(t, err)

	for _, successfulIdentity := range []int{0, 1} {
		t.Run(fmt.Sprint(successfulIdentity), func(t *testing.T) {
			verified := &fakeSig{payload: []byte("verified")}
			unverified := &fakeSig{payload: []byte("unverified")}
			calls := 0
			v := &verifier{
				log:    logrus.NewEntry(logrus.New()),
				optsV3: &cosign.CheckOpts{Identities: identities, NewBundleFormat: true},
				verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
					require.True(t, co.NewBundleFormat)
					require.Equal(t, []cosign.Identity{identities[calls]}, co.Identities)
					calls++
					if calls-1 == successfulIdentity {
						return []oci.Signature{verified}, nil
					}
					return []oci.Signature{unverified}, &cosign.ErrNoMatchingAttestations{}
				},
			}
			ref, err := name.ParseReference("example.com/test/image:tag")
			require.NoError(t, err)
			sigs, err := v.verifyBundleFormat(context.Background(), ref)
			require.NoError(t, err)
			require.Equal(t, []oci.Signature{verified}, sigs)
			require.Equal(t, len(identities), calls)
		})
	}
}

func TestVerifyBundleFormatPreservesV3IdentityErrors(t *testing.T) {
	identities, err := certificateIdentities([]string{"nais"}, "https://issuer.example.org", []string{"nav.no"})
	require.NoError(t, err)
	causes := []error{errors.New("first identity failed"), errors.New("second identity failed")}
	calls := 0
	v := &verifier{
		log:    logrus.NewEntry(logrus.New()),
		optsV3: &cosign.CheckOpts{Identities: identities, NewBundleFormat: true},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			if !co.NewBundleFormat {
				return nil, nil
			}
			require.Equal(t, []cosign.Identity{identities[calls]}, co.Identities)
			err := errors.Join(&cosign.ErrNoMatchingAttestations{}, causes[calls])
			calls++
			return nil, err
		},
	}
	ref, err := name.ParseReference("example.com/test/image:tag")
	require.NoError(t, err)
	sigs, err := v.verifyBundleFormat(context.Background(), ref)
	require.Nil(t, sigs)
	for _, cause := range causes {
		require.ErrorIs(t, err, cause)
	}
	_, ok := errors.AsType[*cosign.ErrNoMatchingAttestations](err)
	require.True(t, ok)
	require.Equal(t, len(identities), calls)
}

func TestGetAttestationRedactsCertificateIdentityErrors(t *testing.T) {
	var logs bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&logs)
	cause := errors.Join(&cosign.ErrNoMatchingAttestations{}, fmt.Errorf("unexpected certificate subject: signer@nav.no"))
	v := &verifier{
		log:    logrus.NewEntry(logger),
		optsV3: &cosign.CheckOpts{NewBundleFormat: true},
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			return nil, cause
		},
	}

	_, err := v.GetAttestation(context.Background(), "example.com/test/image:tag")
	require.ErrorIs(t, err, cause)
	_, ok := errors.AsType[*cosign.ErrNoMatchingAttestations](err)
	require.True(t, ok)
	require.NotContains(t, err.Error(), "signer@nav.no")
	require.NotContains(t, logs.String(), "signer@nav.no")
}

func TestGetAttestation_Success(t *testing.T) {
	dsse := loadDSSEFromFile(t, "testdata/cyclonedx-dsse.json")
	st, err := ParseEnvelope(dsse)
	require.NoError(t, err)
	rBundle := loadRekorBundleFromFile(t, "testdata/rekor-bundle.json")

	v := &verifier{
		log:    logrus.NewEntry(logrus.New()),
		optsV3: &cosign.CheckOpts{NewBundleFormat: true},
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
