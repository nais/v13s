package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	gh "github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	ociremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sirupsen/logrus"
)

const (
	ErrNoAttestation = "no matching attestations"
)

type Verifier struct {
	opts *cosign.CheckOpts
	log  *logrus.Entry
}

func NewVerifier(ctx context.Context, log *logrus.Entry, organizations ...string) (*Verifier, error) {
	// TODO: fix for localhost
	//ids := github.NewCertificateIdentity(organizations).GetIdentities()
	opts, err := CosignOptions(ctx, "", []cosign.Identity{})
	if err != nil {
		return nil, err
	}

	return &Verifier{
		opts: opts,
		log:  log,
	}, nil
}

func (v *Verifier) GetAttestation(ctx context.Context, image string) (*in_toto.CycloneDXStatement, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, fmt.Errorf("parse reference: %v", err)
	}

	verified, _, err := cosign.VerifyImageAttestations(ctx, ref, v.opts)
	if err != nil {
		if strings.Contains(err.Error(), ErrNoAttestation) {
			v.log.Debug("no attestations found")
			return nil, err
		}
		v.log.Warn("verifying image attestations")
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
	}).Info("attestation verified and parsed statement")

	return statement, nil
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
