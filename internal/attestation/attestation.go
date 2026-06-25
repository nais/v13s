package attestation

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	gh "github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/google"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/nais/v13s/internal/attestation/github"
	"github.com/nais/v13s/internal/model"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	ErrNoAttestation = "no matching attestations"
)

var errNoCycloneDXAttestationInBundles = errors.New("no CycloneDX attestation found in verified bundles")

type Verifier interface {
	GetAttestation(ctx context.Context, image string) (*Attestation, error)
}

var _ Verifier = &verifier{}

type verifier struct {
	log        *logrus.Entry
	optsV3     *cosign.CheckOpts
	remoteOpts []gcrremote.Option
	verifyFunc func(ctx context.Context, ref name.Reference, co *cosign.CheckOpts) ([]oci.Signature, error)
	getBundles func(ctx context.Context, signedImgRef name.Reference, registryClientOpts []cosignremote.Option, nameOpts ...name.Option) ([]*bundle.Bundle, *v1.Hash, error)
	verifyNew  func(ctx context.Context, co *cosign.CheckOpts, artifactPolicyOption verify.ArtifactPolicyOption, entity verify.SignedEntity) (*verify.VerificationResult, error)
	headFunc   func(ref name.Reference, options ...gcrremote.Option) (*v1.Descriptor, error)
}

func NewVerifier(_ context.Context, log *logrus.Entry, organizations ...string) (Verifier, error) {
	ids := github.NewCertificateIdentity(organizations).GetIdentities()

	keychain := authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		gh.Keychain,
	)
	remoteOpts := []gcrremote.Option{
		gcrremote.WithAuthFromKeychain(keychain),
	}
	registryOpts := []cosignremote.Option{
		cosignremote.WithRemoteOptions(remoteOpts...),
	}

	trustedRoot, err := cosign.TrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("getting trusted root: %w", err)
	}
	if trustedRoot == nil {
		return nil, fmt.Errorf("trusted root is nil")
	}

	v := &verifier{
		log: log,
		optsV3: &cosign.CheckOpts{
			RegistryClientOpts: registryOpts,
			NewBundleFormat:    true,
			TrustedMaterial:    trustedRoot,
			Identities:         ids,
		},
		remoteOpts: remoteOpts,
		getBundles: cosign.GetBundles,
		verifyNew:  cosign.VerifyNewBundle,
		headFunc:   gcrremote.Head,
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
	defer func() { _ = writer.Close() }()
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
	defer func() { _ = reader.Close() }()

	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var attestation *Attestation
	if err := json.Unmarshal(b, &attestation); err != nil {
		return nil, err
	}
	if attestation == nil {
		return nil, fmt.Errorf("attestation payload is null")
	}

	if attestation.Metadata == nil {
		attestation.Metadata = map[string]string{}
	}

	return attestation, nil
}

func (v *verifier) verifyBundleFormat(ctx context.Context, ref name.Reference) ([]oci.Signature, error) {
	coV3 := *v.optsV3
	coV3.NewBundleFormat = true

	sigs, err := v.verifyFunc(ctx, ref, &coV3)
	if err == nil && len(sigs) > 0 {
		return sigs, nil
	}

	shouldFallback := len(sigs) == 0
	var noMatch *cosign.ErrNoMatchingAttestations
	if errors.As(err, &noMatch) {
		shouldFallback = true
	}

	if !shouldFallback {
		// v3 failed for a "real" reason (not just absence)
		return nil, err
	}

	v.log.WithFields(logrus.Fields{
		"ref": ref.String(),
	}).Info("No v3 attestations (or v3 reported none), switching to legacy bundle format")

	coLegacy := *v.optsV3
	coLegacy.NewBundleFormat = false

	legacySigs, legacyErr := v.verifyFunc(ctx, ref, &coLegacy)
	if legacyErr == nil && len(legacySigs) > 0 {
		return legacySigs, nil
	}

	// Prefer legacy error if we tried it; otherwise return v3 error
	if legacyErr != nil {
		var noMatch *cosign.ErrNoMatchingAttestations
		if errors.As(legacyErr, &noMatch) {
			v.log.WithError(legacyErr).WithField("ref", ref.String()).Info("legacy attestation reported no matching attestations")
			return nil, legacyErr
		}

		v.log.WithError(legacyErr).WithField("ref", ref.String()).Warn("legacy attestation verification failed")
		return nil, legacyErr
	}
	// legacyErr == nil but no sigs
	return nil, err // err might be nil; if so, caller will treat as no attestation
}

func (v *verifier) GetAttestation(ctx context.Context, image string) (*Attestation, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, model.ToUnrecoverableError(fmt.Errorf("parse reference: %v", err), "attestation")
	}

	att, err := v.getAttestationFromNewBundle(ctx, ref)
	if err == nil {
		return att, nil
	}

	if !shouldFallbackToLegacy(err) {
		return nil, err
	}

	v.log.WithFields(logrus.Fields{
		"ref": ref.String(),
	}).WithError(err).Info("new-bundle attestation path had no usable CycloneDX payload, falling back to legacy verification")

	return v.getAttestationFromLegacyVerify(ctx, ref)
}

func (v *verifier) getAttestationFromNewBundle(ctx context.Context, ref name.Reference) (*Attestation, error) {
	if v.getBundles == nil || v.verifyNew == nil {
		return nil, errNoCycloneDXAttestationInBundles
	}

	bundles, hash, err := v.getBundles(ctx, ref, v.optsV3.RegistryClientOpts)
	if err != nil {
		return nil, mapTransportError(err)
	}
	if hash == nil {
		return nil, errNoCycloneDXAttestationInBundles
	}

	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return nil, err
	}

	artifactPolicy := verify.WithArtifactDigest(hash.Algorithm, digestBytes)

	for _, b := range bundles {
		result, verifyErr := v.verifyNew(ctx, v.optsV3, artifactPolicy, b)
		if verifyErr != nil {
			v.log.WithError(verifyErr).Debug("new-bundle verification failed for one bundle")
			continue
		}

		att, fromResultErr := attestationFromVerificationResult(result)
		if fromResultErr != nil {
			v.log.WithError(fromResultErr).Debug("verified bundle did not contain a usable CycloneDX statement")
			continue
		}

		if result != nil && result.Signature != nil && result.Signature.Certificate != nil {
			att.Metadata = metadataFromCertificateSummary(result.Signature.Certificate)
			if len(att.Metadata) == 0 {
				v.log.Debug("verified CycloneDX statement has no signer metadata in certificate summary")
			}
		}
		if att.Metadata == nil {
			att.Metadata = map[string]string{}
		}
		att.Metadata["imageDigest"] = formatHash(*hash)

		v.log.WithField("ref", ref.String()).Debug("attestation verified and extracted through new-bundle path")
		return att, nil
	}

	return nil, errNoCycloneDXAttestationInBundles
}

func (v *verifier) getAttestationFromLegacyVerify(ctx context.Context, ref name.Reference) (*Attestation, error) {
	verified, err := v.verifyBundleFormat(ctx, ref)
	if err != nil {
		var noMatch *cosign.ErrNoMatchingAttestations
		if errors.As(err, &noMatch) {
			return nil, err
		}
		return nil, err
	}
	if len(verified) == 0 {
		return nil, model.ToUnrecoverableError(errors.New(ErrNoAttestation), "attestation")
	}

	chosen, payload, err := pickCycloneDX(verified)
	if err != nil {
		return nil, model.ToRecoverableError(err, "attestation")
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

	ret.Metadata = v.extractMetadata(chosen)
	if digest := v.resolveLegacyImageDigest(chosen, ref); digest != "" {
		ret.Metadata["imageDigest"] = digest
	}

	return ret, nil
}

func shouldFallbackToLegacy(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errNoCycloneDXAttestationInBundles) {
		return true
	}
	var noMatch *cosign.ErrNoMatchingAttestations
	return errors.As(err, &noMatch)
}

func mapTransportError(err error) error {
	if tErr, ok := errors.AsType[*transport.Error](err); ok {
		if tErr.StatusCode >= 400 && tErr.StatusCode < 500 {
			return model.ToUnrecoverableError(
				fmt.Errorf("status: %d, error: %w", tErr.StatusCode, tErr),
				"attestation",
			)
		}
		return model.ToRecoverableError(tErr, "attestation")
	}
	return err
}

// pickCycloneDX finds the CycloneDX attestation (order-independent) and returns the signature + its payload.
func pickCycloneDX(verified []oci.Signature) (oci.Signature, []byte, error) {
	for _, sig := range verified {
		env, err := sig.Payload()
		if err != nil {
			logrus.Debugf("pickCycloneDX: failed to get payload: %v", err)
			continue
		}
		st, err := ParseEnvelope(env)
		if err != nil {
			logrus.Debugf("pickCycloneDX: failed to parse envelope: %v", err)
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
	return &Attestation{
		Predicate: predicate,
		Metadata:  map[string]string{},
	}, nil
}

func attestationFromVerificationResult(result *verify.VerificationResult) (*Attestation, error) {
	if result == nil || result.Statement == nil {
		return nil, fmt.Errorf("verification result has no statement")
	}

	statementJSON, err := protojson.Marshal(result.Statement)
	if err != nil {
		return nil, fmt.Errorf("marshal verified statement: %w", err)
	}

	statement := &in_toto.CycloneDXStatement{}
	if err := json.Unmarshal(statementJSON, statement); err != nil {
		return nil, fmt.Errorf("unmarshal verified statement: %w", err)
	}

	if statement.PredicateType != in_toto.PredicateCycloneDX {
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.PredicateType)
	}

	return attestationFromStatement(statement)
}

// extractMetadata is intentionally best-effort (never fails GetAttestation).
func (v *verifier) extractMetadata(sig oci.Signature) map[string]string {
	metadata := map[string]string{}
	cert, err := sig.Cert()
	if err != nil {
		v.log.WithError(err).Debug("extractMetadata: sig.Cert failed")
		return metadata
	}
	if cert == nil {
		v.log.Debug("extractMetadata: sig.Cert returned nil cert; trying sig.Chain")
		chain, chainErr := sig.Chain()
		if chainErr != nil {
			v.log.WithError(chainErr).Debug("extractMetadata: sig.Chain failed")
			return metadata
		}
		if len(chain) == 0 || chain[0] == nil {
			v.log.Debug("extractMetadata: sig.Chain returned no certificates")
			return metadata
		}
		cert = chain[0]
	}

	certMetadata := GetCertificateMetadata(cert)

	return metadataFromCertificateMetadata(certMetadata)
}

func metadataFromCertificateSummary(summary *fulciocert.Summary) map[string]string {
	if summary == nil {
		return map[string]string{}
	}
	return metadataFromCertificateMetadata(GetCertificateMetadataFromSummary(summary))
}

func metadataFromCertificateMetadata(certMetadata *CertificateMetadata) map[string]string {
	metadata := map[string]string{}

	j, err := json.Marshal(certMetadata)
	if err != nil {
		return metadata
	}

	if err = json.Unmarshal(j, &metadata); err != nil {
		return metadata
	}
	return metadata
}

func formatHash(hash v1.Hash) string {
	if hash.Algorithm == "" || hash.Hex == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", hash.Algorithm, hash.Hex)
}

func (v *verifier) resolveImageDigest(ref name.Reference) string {
	if digest := digestFromReference(ref); digest != "" {
		return digest
	}
	if v.headFunc == nil {
		return ""
	}
	desc, err := v.headFunc(ref, v.remoteOpts...)
	if err != nil {
		v.log.WithError(err).WithField("ref", ref.String()).Debug("resolveImageDigest: registry head failed")
		return ""
	}
	if desc == nil {
		return ""
	}
	return desc.Digest.String()
}

func (v *verifier) resolveLegacyImageDigest(sig oci.Signature, ref name.Reference) string {
	if digest := v.resolveImageDigest(ref); digest != "" {
		return digest
	}
	if sig != nil {
		hash, err := sig.Digest()
		if err == nil {
			if digest := formatHash(hash); digest != "" {
				return digest
			}
		} else {
			v.log.WithError(err).WithField("ref", ref.String()).Debug("resolveLegacyImageDigest: signature digest failed")
		}
	}
	return ""
}

func digestFromReference(ref name.Reference) string {
	if ref == nil {
		return ""
	}
	value := ref.String()
	at := strings.LastIndex(value, "@")
	if at == -1 || at == len(value)-1 {
		return ""
	}
	return value[at+1:]
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
