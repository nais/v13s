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
	"strings"

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
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sirupsen/logrus"
)

const (
	ErrNoAttestation           = "no matching attestations"
	ErrNoValidBundleInRegistry = "no valid bundles exist in registry"
)

type Verifier interface {
	GetAttestation(ctx context.Context, image string) (*Attestation, error)
}

var _ Verifier = &verifier{}

type verifier struct {
	log *logrus.Entry

	optsV3     *cosign.CheckOpts
	optsLegacy *cosign.CheckOpts

	verifyFunc func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error)
}

func NewVerifier(ctx context.Context, log *logrus.Entry, organizations ...string) (Verifier, error) {
	ids := github.NewCertificateIdentity(organizations).GetIdentities()

	keychain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		gh.Keychain,
	)
	registryOpts := []remote.Option{
		remote.WithRemoteOptions(ociremote.WithAuthFromKeychain(keychain)),
	}

	trustedRoot, err := cosign.TrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("getting trusted root: %w", err)
	}

	rootCerts, err := fulcio.GetRoots()
	if err != nil {
		return nil, fmt.Errorf("getting Fulcio roots: %w", err)
	}
	intermediateCerts, err := fulcio.GetIntermediates()
	if err != nil {
		return nil, fmt.Errorf("getting Fulcio intermediates: %w", err)
	}
	rekorPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting Rekor public keys: %w", err)
	}
	ctLogPubKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting CT log public keys: %w", err)
	}

	v := &verifier{
		log: log,
		optsV3: &cosign.CheckOpts{
			RegistryClientOpts: registryOpts,
			NewBundleFormat:    true,
			TrustedMaterial:    trustedRoot,
			Identities:         ids,
		},
		optsLegacy: &cosign.CheckOpts{
			RegistryClientOpts: registryOpts,
			NewBundleFormat:    false,
			Identities:         ids,
			RootCerts:          rootCerts,
			IntermediateCerts:  intermediateCerts,
			RekorPubKeys:       rekorPubKeys,
			CTLogPubKeys:       ctLogPubKeys,
		},
	}

	v.verifyFunc = func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error) {
		sigs, _, err := cosign.VerifyImageAttestations(ctx, ref, co)

		var tErr *transport.Error
		if errors.As(err, &tErr) {
			if tErr.StatusCode >= 400 && tErr.StatusCode < 500 {
				return sigs, model.ToUnrecoverableError(
					fmt.Errorf("status: %d, error: %w", tErr.StatusCode, tErr),
					"attestation",
				)
			}
			return sigs, model.ToRecoverableError(tErr, "attestation")
		}

		return sigs, err
	}

	return v, nil
}

type Attestation struct {
	Predicate []byte            `json:"predicate"`
	Metadata  map[string]string `json:"metadata"`
}

func (a *Attestation) Compress() ([]byte, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
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
	if err := json.Unmarshal(b, &attestation); err != nil {
		return nil, err
	}
	return attestation, nil
}

func (v *verifier) GetAttestation(ctx context.Context, image string) (*Attestation, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, model.ToUnrecoverableError(fmt.Errorf("parse reference: %v", err), "attestation")
	}

	verified, err := v.verifyWithFallback(ctx, ref)
	if err != nil {
		return nil, err
	}
	if len(verified) == 0 {
		return nil, model.ToUnrecoverableError(errors.New(ErrNoAttestation), "attestation")
	}

	chosen, payload, err := pickCycloneDX(verified)
	if err != nil {
		return nil, model.ToUnrecoverableError(err, "attestation")
	}

	statement, err := ParseEnvelope(payload)
	if err != nil {
		return nil, fmt.Errorf("parsing DSSE envelope: %v", err)
	}

	v.log.WithFields(logrus.Fields{
		"predicate-type": statement.PredicateType,
		"statement-type": statement.Type,
		"ref":            ref.String(),
	}).Debug("attestation verified and parsed statement")

	ret, err := attestationFromStatement(statement)
	if err != nil {
		return nil, err
	}

	metadata := v.extractMetadata(chosen)
	if len(metadata) > 0 {
		ret.Metadata = metadata
	}

	return ret, nil
}

// verifyWithFallback tries v3 bundles first, then legacy tag-based attestations.
func (v *verifier) verifyWithFallback(ctx context.Context, ref name.Reference) ([]oci.Signature, error) {
	verified, err := v.verifyFunc(ctx, ref, v.optsV3)
	if err != nil {
		// 4xx => do not fall back
		var tErr *transport.Error
		if errors.As(err, &tErr) && tErr.StatusCode >= 400 && tErr.StatusCode < 500 {
			return nil, err
		}

		// non-attestation error => do not fallback
		if !isNoAttestationOrBundleError(err) {
			return nil, err
		}
	}

	// fallback when v3 produced nothing
	if err != nil || len(verified) == 0 {
		verified, err = v.verifyFunc(ctx, ref, v.optsLegacy)
		if err != nil {
			if isNoAttestationOrBundleError(err) {
				return nil, model.ToUnrecoverableError(errors.New(ErrNoAttestation), "attestation")
			}
			return nil, err
		}
	}
	return verified, nil
}

// pickCycloneDX finds the CycloneDX attestation (order-independent) and returns the signature + its payload.
func pickCycloneDX(verified []oci.Signature) (oci.Signature, []byte, error) {
	for _, sig := range verified {
		env, err := sig.Payload()
		if err != nil {
			continue
		}
		st, err := ParseEnvelope(env)
		if err != nil {
			continue
		}
		if st.PredicateType == in_toto.PredicateCycloneDX {
			return sig, env, nil
		}
	}
	return nil, nil, fmt.Errorf("no CycloneDX attestation found among %d attestations", len(verified))
}

func attestationFromStatement(statement *in_toto.CycloneDXStatement) (*Attestation, error) {
	if statement.PredicateType != in_toto.PredicateCycloneDX {
		return nil, model.ToUnrecoverableError(
			fmt.Errorf("unsupported predicate type: %s", statement.PredicateType),
			"attestation",
		)
	}
	predicate, err := json.Marshal(statement.Predicate)
	if err != nil {
		return nil, fmt.Errorf("marshal predicate: %v", err)
	}
	return &Attestation{Predicate: predicate}, nil
}

// extractMetadata is intentionally best-effort (never fails GetAttestation).
func (v *verifier) extractMetadata(sig oci.Signature) map[string]string {
	b, err := sig.Bundle()
	if err != nil || b == nil {
		return nil
	}

	rekor, err := GetRekorMetadata(b)
	if err != nil {
		return nil
	}

	j, err := json.Marshal(rekor)
	if err != nil {
		return nil
	}

	metadata := map[string]string{}
	if err := json.Unmarshal(j, &metadata); err != nil {
		return nil
	}
	return metadata
}

func isNoAttestationOrBundleError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, ErrNoAttestation) ||
		strings.Contains(msg, ErrNoValidBundleInRegistry)
}

func ParseEnvelope(dsseEnvelope []byte) (*in_toto.CycloneDXStatement, error) {
	env := ssldsse.Envelope{}
	if err := json.Unmarshal(dsseEnvelope, &env); err != nil {
		return nil, err
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	stat := &in_toto.CycloneDXStatement{}
	if err := json.Unmarshal(decodedPayload, &stat); err != nil {
		return nil, err
	}
	return stat, nil
}
