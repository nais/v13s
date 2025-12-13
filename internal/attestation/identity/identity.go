package identity

import (
	"regexp"

	"github.com/nais/v13s/internal/config"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sirupsen/logrus"
)

func GetIdentities(cfg config.IdentityEnforcementConfig, log *logrus.Entry) []cosign.Identity {
	log = log.WithField("component", "identity_enforcement")

	log.Infof("setting up identity enforcement configuration (enabled=%v)", cfg.Enabled)

	if !cfg.Enabled {
		return nil
	}

	if len(cfg.Identities) == 0 {
		log.Warn("identity enforcement is enabled, but no allowed identities are configured")
		return []cosign.Identity{}
	}

	identities := make([]cosign.Identity, 0, len(cfg.Identities))
	log.Infof("configuring %d allowed identities", len(cfg.Identities))

	for i, allowed := range cfg.Identities {
		re, err := regexp.Compile(allowed.Subject)
		if err != nil {
			log.WithFields(logrus.Fields{
				"issuer": allowed.Issuer,
				"regex":  allowed.Subject,
				"error":  err,
			}).Errorf("invalid subject regex in identity #%d; skipping", i)
			continue
		}

		log.WithFields(logrus.Fields{
			"issuer": allowed.Issuer,
			"regex":  re.String(),
		}).Debug("added identity rule")

		identities = append(identities, cosign.Identity{
			Issuer:        allowed.Issuer,
			SubjectRegExp: re.String(),
		})
	}

	if len(identities) == 0 {
		log.Warn("all configured identities were invalid; identity enforcement will accept any identity")
	}

	return identities
}
