package attestation

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	gh "github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	ociremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/nais/v13s/internal/attestation/github"
	"github.com/nais/v13s/internal/model"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sirupsen/logrus"
)

const (
	ErrNoAttestation = "no matching attestations"
)

type Verifier interface {
	GetAttestation(ctx context.Context, image string) (*Attestation, error)
}

var _ Verifier = &verifier{}

type VerifyFunc func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, *cosign.CheckOpts, error)

type verifier struct {
	opts       *cosign.CheckOpts
	log        *logrus.Entry
	verifyFunc func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error)
}

func NewVerifier(ctx context.Context, log *logrus.Entry, organizations ...string) (Verifier, error) {
	ids := github.NewCertificateIdentity(organizations).GetIdentities()
	opts, err := CosignOptions(ctx, "", ids)
	if err != nil {
		return nil, err
	}

	return &verifier{
		opts: opts,
		log:  log,
		verifyFunc: func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
			sigs, _, err := cosign.VerifyImageAttestations(ctx, ref, co)
			var tErr *transport.Error
			if errors.As(err, &tErr) {
				if tErr.StatusCode < 500 && tErr.StatusCode >= 400 {
					return sigs, model.ToUnrecoverableError(tErr, "attestation")
				} else {
					return sigs, model.ToRecoverableError(tErr, "attestation")
				}
			}
			return sigs, err
		},
	}, nil
}

type Attestation struct {
	Statement *in_toto.CycloneDXStatement `json:"statement"`
	Metadata  map[string]string           `json:"metadata"`
}

func (a *Attestation) Compress() ([]byte, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	_, err = writer.Write(data)
	if err != nil {
		return nil, err
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func Decompress(data []byte) (*Attestation, error) {
	buffer := bytes.NewBuffer(data)
	reader, err := gzip.NewReader(buffer)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var attestation *Attestation
	err = json.Unmarshal(b, &attestation)
	if err != nil {
		return nil, err
	}
	return attestation, nil
}

func (v *verifier) GetAttestation(ctx context.Context, image string) (*Attestation, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, model.ToUnrecoverableError(fmt.Errorf("parse reference: %v", err), "attestation")
	}

	verified, err := v.verifyFunc(ctx, ref, v.opts)
	if err != nil {
		return nil, err
	}
	att := verified[len(verified)-1]

	env, err := att.Payload()
	if err != nil {
		return nil, fmt.Errorf("get payload: %v", err)
	}
	statement, err := ParseEnvelope(env)
	if err != nil {
		return nil, fmt.Errorf("parse payload: %v", err)
	}
	v.log.WithFields(logrus.Fields{
		"predicate-type": statement.PredicateType,
		"statement-type": statement.Type,
		"ref":            ref.String(),
	}).Debug("attestation verified and parsed statement")

	if statement.PredicateType != in_toto.PredicateCycloneDX {
		return nil, model.ToUnrecoverableError(fmt.Errorf("unsupported predicate type: %s", statement.PredicateType), "attestation")
	}

	ret := &Attestation{
		Statement: statement,
	}

	// TODO: find an easier way to get the metadata
	bundle, err := att.Bundle()
	if err != nil {
		v.log.Warnf("failed to get bundle: %v", err)
		return ret, nil
	}
	rekor, err := GetRekorMetadata(bundle)
	if err != nil {
		v.log.Warnf("failed to get rekor metadata: %v", err)
		return ret, nil
	}

	j, err := json.Marshal(rekor)
	if err != nil {
		v.log.Warnf("failed to marshal metadata: %v", err)
		return ret, nil
	}

	metadata := map[string]string{}
	err = json.Unmarshal(j, &metadata)
	if err != nil {
		v.log.Warnf("failed to unmarshal metadata: %v", err)
		return ret, nil
	}

	ret.Metadata = metadata

	return ret, nil
}

func CosignOptions(ctx context.Context, staticKeyRef string, identities []cosign.Identity) (*cosign.CheckOpts, error) {
	co := &cosign.CheckOpts{}

	var err error
	if !co.IgnoreSCT {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	if staticKeyRef == "" {
		// This performs an online fetch of the Fulcio roots. This is needed
		// for verifying keyless certificates (both online and offline).
		co.RootCerts, err = fulcio.GetRoots()
		if err != nil {
			return nil, fmt.Errorf("getting Fulcio roots: %w", err)
		}
		co.IntermediateCerts, err = fulcio.GetIntermediates()
		if err != nil {
			return nil, fmt.Errorf("getting Fulcio intermediates: %w", err)
		}
		co.Identities = identities

		// This performs an online fetch of the Rekor public keys, but this is needed
		// for verifying tlog entries (both online and offline).
		co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting Rekor public keys: %w", err)
		}
	}

	if staticKeyRef != "" {
		// ensure that the static public key is used
		// vao.KeyRef = vao.StaticKeyRef
		co.SigVerifier, err = signature.PublicKeyFromKeyRef(ctx, staticKeyRef)
		if err != nil {
			return nil, fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
		co.IgnoreTlog = true
	}

	keychain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		gh.Keychain,
	)

	co.RegistryClientOpts = []remote.Option{
		remote.WithRemoteOptions(ociremote.WithAuthFromKeychain(keychain)),
	}

	return co, nil
}

func ParseEnvelope(dsseEnvelope []byte) (*in_toto.CycloneDXStatement, error) {
	env := ssldsse.Envelope{}
	err := json.Unmarshal(dsseEnvelope, &env)
	if err != nil {
		return nil, err
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	stat := &in_toto.CycloneDXStatement{}
	err = json.Unmarshal(decodedPayload, &stat)
	if err != nil {
		return nil, err
	}
	return stat, nil
}
