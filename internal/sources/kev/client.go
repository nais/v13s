package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

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

type FetchResult struct {
	Catalog *Catalog
}

type Client struct {
	httpClient *http.Client
	catalogURL string
}

func NewClientWithURL(url string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		catalogURL: url,
	}
}

func (c *Client) FetchCatalog(ctx context.Context) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.catalogURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building KEV request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching KEV catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV catalog returned HTTP %d", resp.StatusCode)
	}

	var catalog Catalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decoding KEV catalog: %w", err)
	}

	return &FetchResult{
		Catalog: &catalog,
	}, nil
}
