package attestation

import (
	"crypto/x509"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
)

type fakeSig struct {
	payload []byte
	bundle  *bundle.RekorBundle
}

func (f *fakeSig) Digest() (v1.Hash, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) DiffID() (v1.Hash, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Compressed() (io.ReadCloser, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Uncompressed() (io.ReadCloser, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Annotations() (map[string]string, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Size() (int64, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) MediaType() (types.MediaType, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Signature() ([]byte, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Base64Signature() (string, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Cert() (*x509.Certificate, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Chain() ([]*x509.Certificate, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Bundle() (*bundle.RekorBundle, error) {
	return f.bundle, nil
}

func (f *fakeSig) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) {
	// TODO implement me
	panic("implement me")
}

func (f *fakeSig) Payload() ([]byte, error) {
	return f.payload, nil
}
