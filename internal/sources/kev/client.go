package kev

import (
	"context"

	"github.com/nais/v13s/internal/httpclient"
)

const SourceCISA = "cisa"

type Catalog struct {
	Title           string  `json:"title"`
	CatalogVersion  string  `json:"catalogVersion"`
	DateReleased    string  `json:"dateReleased"`
	Count           int     `json:"count"`
	Vulnerabilities []Entry `json:"vulnerabilities"`
}

type Entry struct {
	CveID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

func (e Entry) KnownRansomware() bool {
	return e.KnownRansomwareCampaignUse == "Known"
}

type CisaClient struct {
	http httpclient.Doer
	url  string
}

func NewCisaClient(url string) *CisaClient {
	return &CisaClient{
		http: httpclient.New(feedTimeout),
		url:  url,
	}
}

func (c *CisaClient) Name() string { return SourceCISA }

func (c *CisaClient) Fetch(ctx context.Context) ([]Assertion, error) {
	var catalog Catalog
	if err := httpclient.GetJSON(ctx, c.http, c.url, nil, &catalog); err != nil {
		return nil, err
	}

	assertions := make([]Assertion, 0, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		assertions = append(assertions, Assertion{CveID: v.CveID, KnownRansomware: v.KnownRansomware()})
	}
	return assertions, nil
}
