package cveexplanation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/nais/v13s/internal/httpclient"
	"github.com/nais/v13s/internal/sources/kev"
)

const (
	PromptVersion = int32(1)
	CatalogURL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type Input struct {
	CveID           string `json:"cve_id"`
	Title           string `json:"title"`
	Description     string `json:"description"`
	RequiredAction  string `json:"required_action"`
	DueDate         string `json:"cisa_due_date"`
	KnownRansomware bool   `json:"known_ransomware_use"`
}

func (i Input) validate() error {
	if !cveIDPattern.MatchString(i.CveID) || strings.TrimSpace(i.Description) == "" {
		return errors.New("invalid public CVE input")
	}
	data, _ := json.Marshal(i)
	if len(data) > 16000 {
		return errors.New("public CVE input exceeds size limit")
	}
	return nil
}

func (i Input) hash() string {
	data, _ := json.Marshal(i)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

type Catalog interface {
	Fetch(context.Context) (map[string]Input, error)
}

type CisaCatalog struct {
	http httpclient.Doer
}

func NewCisaCatalog() *CisaCatalog {
	return &CisaCatalog{http: httpclient.New(callTimeout)}
}

func (c *CisaCatalog) Fetch(ctx context.Context) (map[string]Input, error) {
	var catalog kev.Catalog
	if err := httpclient.GetJSON(ctx, c.http, CatalogURL, nil, &catalog); err != nil {
		return nil, errors.New("fetching public CISA explanation catalog failed")
	}
	inputs := make(map[string]Input, len(catalog.Vulnerabilities))
	for _, entry := range catalog.Vulnerabilities {
		input := Input{
			CveID:           entry.CveID,
			Title:           entry.VulnerabilityName,
			Description:     entry.ShortDescription,
			RequiredAction:  entry.RequiredAction,
			DueDate:         entry.DueDate,
			KnownRansomware: entry.KnownRansomware(),
		}
		if err := input.validate(); err != nil {
			continue
		}
		if _, duplicate := inputs[input.CveID]; duplicate {
			return nil, errors.New("duplicate CVE in public CISA explanation catalog")
		}
		inputs[input.CveID] = input
	}
	if len(inputs) == 0 {
		return nil, errors.New("public CISA explanation catalog contains no valid entries")
	}
	return inputs, nil
}
