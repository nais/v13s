package kev

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/nais/v13s/internal/httpclient"
)

const SourceENISA = "enisa"

type enisaEntry struct {
	CveID            string            `json:"cveID"`
	ExploitationType exploitationTypes `json:"exploitationType"`
}

// exploitationTypes accepts a string or an array of strings; the feed is normally a string but has shipped arrays.
type exploitationTypes []string

func (t *exploitationTypes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*t = exploitationTypes{s}
		return nil
	}
	var a []string
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*t = a
	return nil
}

func (t exploitationTypes) ransomware() bool {
	return slices.ContainsFunc(t, func(v string) bool { return strings.EqualFold(v, "ransomware") })
}

type EnisaClient struct {
	http httpclient.Doer
	url  string
}

func NewEnisaClient(url string) *EnisaClient {
	return &EnisaClient{
		http: httpclient.New(feedTimeout),
		url:  url,
	}
}

func (c *EnisaClient) Name() string { return SourceENISA }

func (c *EnisaClient) Fetch(ctx context.Context) ([]Assertion, error) {
	var entries []enisaEntry
	if err := httpclient.GetJSON(ctx, c.http, c.url, nil, &entries); err != nil {
		return nil, err
	}

	assertions := make([]Assertion, 0, len(entries))
	for _, e := range entries {
		if e.CveID == "" {
			continue
		}
		assertions = append(assertions, Assertion{
			CveID:           e.CveID,
			KnownRansomware: e.ExploitationType.ransomware(),
		})
	}
	return assertions, nil
}
