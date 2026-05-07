package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/blang/semver"
)

type VulnRecord struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases"`
	Affected []Affected `json:"affected"`
}

type Affected struct {
	Package AffectedPackage `json:"package"`
	Ranges  []Range         `json:"ranges"`
}

type AffectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type Client struct {
	httpClient *http.Client
	baseURL    string
}

func NewClientWithURL(baseURL string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    baseURL,
	}
}

// FetchVuln fetches an OSV record by ID. Returns nil when the ID is unknown.
// On 404, the response body may hint at GHSA aliases — returned as a stub so the caller can follow them.
func (c *Client) FetchVuln(ctx context.Context, id string) (*VulnRecord, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, fmt.Errorf("building OSV request for %s: %w", id, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OSV vuln %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return decodeAliasHints(id, resp)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV vuln %s returned HTTP %d", id, resp.StatusCode)
	}

	return decodeVulnRecord(id, resp)
}

func decodeAliasHints(id string, resp *http.Response) (*VulnRecord, error) {
	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Message == "" {
		return nil, nil
	}
	aliases := ghsaPattern.FindAllString(body.Message, -1)
	if len(aliases) == 0 {
		return nil, nil
	}
	return &VulnRecord{ID: id, Aliases: aliases}, nil
}

// decodeVulnRecord decodes a successful OSV response. HTTP 200 with {"code":5} means unknown — treated as nil.
func decodeVulnRecord(id string, resp *http.Response) (*VulnRecord, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding OSV response for %s: %w", id, err)
	}
	var check struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(raw, &check); err == nil && check.Code != 0 {
		return nil, nil
	}
	var record VulnRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("parsing OSV record for %s: %w", id, err)
	}
	return &record, nil
}

// FixVersionForPurl returns the minimum fix version strictly greater than the installed version.
// OSV may have multiple Affected entries per release branch; all are scanned and the smallest qualifying fix is chosen.
func FixVersionForPurl(record *VulnRecord, storedPurl string) string {
	if record == nil {
		return ""
	}
	base := purlBase(storedPurl)
	installedRaw := purlVersion(storedPurl)
	installed, installedOk := parseSemver(installedRaw)

	var best string
	var bestSemver semver.Version

	for _, a := range record.Affected {
		if a.Package.Purl == "" || !strings.EqualFold(purlBase(a.Package.Purl), base) {
			continue
		}
		candidate, candidateSemver, ok := minFixFromRanges(a.Ranges, installed, installedOk)
		if !ok {
			continue
		}
		if installedOk {
			if best == "" || candidateSemver.LT(bestSemver) {
				best = candidate
				bestSemver = candidateSemver
			}
		} else if best == "" {
			best = candidate
		}
	}

	typ := purlType(storedPurl)
	if typ == "maven" && mavenPreRelease.MatchString(best) {
		return ""
	}
	best = matchClassifier(best, installedRaw)
	if best != "" && typ == "golang" && strings.HasPrefix(installedRaw, "v") && !strings.HasPrefix(best, "v") {
		best = "v" + best
	}
	return best
}

// minFixFromRanges returns the smallest fix version strictly greater than installed, preferring SEMVER > ECOSYSTEM > GIT.
func minFixFromRanges(ranges []Range, installed semver.Version, installedOk bool) (string, semver.Version, bool) {
	for _, rangeType := range []string{"SEMVER", "ECOSYSTEM", "GIT"} {
		best, bestSemver, found := minFixFromRangeType(ranges, rangeType, installed, installedOk)
		if found {
			return best, bestSemver, true
		}
	}
	return "", semver.Version{}, false
}

func minFixFromRangeType(ranges []Range, rangeType string, installed semver.Version, installedOk bool) (string, semver.Version, bool) {
	var best string
	var bestSemver semver.Version

	for _, r := range ranges {
		if r.Type != rangeType {
			continue
		}
		for _, e := range r.Events {
			if e.Fixed == "" {
				continue
			}
			fixed, fixedOk := parseSemver(e.Fixed)
			if installedOk && fixedOk {
				if !fixed.GT(installed) {
					continue
				}
				if best == "" || fixed.LT(bestSemver) {
					best = e.Fixed
					bestSemver = fixed
				}
			} else if best == "" {
				best = e.Fixed
			}
		}
	}
	return best, bestSemver, best != ""
}

// matchClassifier replaces the fix version's classifier with the installed version's (e.g. -android → -jre).
func matchClassifier(fix, installedRaw string) string {
	if fix == "" {
		return fix
	}
	im := classifierSuffix.FindStringSubmatch(installedRaw)
	fm := classifierSuffix.FindStringSubmatch(fix)
	if im == nil || fm == nil || im[1] == fm[1] {
		return fix
	}
	return classifierSuffix.ReplaceAllString(fix, "-"+im[1])
}

func isGHSA(id string) bool {
	return strings.HasPrefix(id, "GHSA-")
}

func parseSemver(v string) (semver.Version, bool) {
	sv, err := semver.ParseTolerant(normalizeVersion(strings.TrimPrefix(v, "v")))
	return sv, err == nil
}

// normalizeVersion strips suffixes blang/semver cannot parse (.Final, .jre11, .Alpha1) and drops a 4th numeric segment.
func normalizeVersion(v string) string {
	for {
		s := nonSemverSuffix.ReplaceAllString(v, "")
		if s == v {
			break
		}
		v = s
	}
	if m := fourthNumericSegment.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return v
}

var (
	classifierSuffix     = regexp.MustCompile(`-([A-Za-z][A-Za-z0-9]*)$`)
	ghsaPattern          = regexp.MustCompile(`GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}`)
	nonSemverSuffix      = regexp.MustCompile(`\.[A-Za-z][A-Za-z0-9]*$`)
	fourthNumericSegment = regexp.MustCompile(`^(\d+\.\d+\.\d+)\.\d+$`)
	mavenPreRelease      = regexp.MustCompile(`(?i)[.\-](M[0-9]+|RC[0-9]+|alpha[0-9]*|beta[0-9]*|SNAPSHOT)$`)
)
