package attestation

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
)

// fakeSig implements oci.Signature (and whatever embedded interfaces your build requires)
// with only the methods your GetAttestation() calls behaving meaningfully.
type fakeSig struct {
	payload []byte
	cert    *x509.Certificate
	chain   []*x509.Certificate
	digest  v1.Hash
}

func (f *fakeSig) Payload() ([]byte, error) { return f.payload, nil }
func (f *fakeSig) Bundle() (*bundle.RekorBundle, error) {
	return nil, nil
}

// ---- Everything below can be stubbed (no panics) ----

func (f *fakeSig) Digest() (v1.Hash, error) { return f.digest, nil }
func (f *fakeSig) DiffID() (v1.Hash, error) { return v1.Hash{}, nil }

func (f *fakeSig) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (f *fakeSig) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (f *fakeSig) Annotations() (map[string]string, error) { return map[string]string{}, nil }
func (f *fakeSig) Size() (int64, error)                    { return 0, nil }
func (f *fakeSig) MediaType() (types.MediaType, error)     { return "", nil }

func (f *fakeSig) Signature() ([]byte, error) {
	return nil, errors.New("fakeSig.Signature should not be called")
}

func (f *fakeSig) Base64Signature() (string, error) {
	// For attestations, cosign often has empty Base64Signature; returning empty is fine
	return base64.StdEncoding.EncodeToString(nil), nil
}

func (f *fakeSig) Cert() (*x509.Certificate, error) {
	return f.cert, nil
}

func (f *fakeSig) Chain() ([]*x509.Certificate, error) { return f.chain, nil }

func (f *fakeSig) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) { return nil, nil }
