package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scalibr/semantic"
)

type VulnRecord struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases"`
	Affected []Affected `json:"affected"`
}

type Affected struct {
	Package  AffectedPackage `json:"package"`
	Ranges   []Range         `json:"ranges"`
	Versions []string        `json:"versions"`
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
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
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
// On 404, the response body may hint at aliases — returned as a stub so the caller can follow them.
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

// decodeAliasHints parses the "...aliases were: X, Y" hint from a 404 body — the alias may be
// any id scheme (GHSA-, GO-, ...), not just GHSA.
func decodeAliasHints(id string, resp *http.Response) (*VulnRecord, error) {
	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Message == "" {
		return nil, nil
	}
	_, hint, found := strings.Cut(body.Message, "aliases were: ")
	if !found {
		return nil, nil
	}
	var aliases []string
	for _, a := range aliasHintSeparator.Split(strings.TrimSpace(hint), -1) {
		if a != "" {
			aliases = append(aliases, a)
		}
	}
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

type MissReason string

const (
	MissNone             MissReason = ""
	MissNotInOsv         MissReason = "not_in_osv"
	MissPackageNotListed MissReason = "package_not_listed"
	MissNoFixUpstream    MissReason = "no_fix_upstream"
	MissInstalledPastFix MissReason = "installed_past_fix"
	MissUnknown          MissReason = "unknown"
)

// FixVersionForPurl returns the minimum fix version strictly greater than the installed version.
// OSV may have multiple Affected entries per release branch; all are scanned and the smallest qualifying fix is chosen.
func FixVersionForPurl(record *VulnRecord, storedPurl string) (string, MissReason) {
	if record == nil {
		return "", MissNotInOsv
	}
	pkg, ok := parsePurl(storedPurl)
	if !ok {
		return "", MissUnknown
	}
	installed, installedOk := parseVersion(pkg.typ, pkg.version)
	if installedState(record.Affected, pkg, installed, installedOk) == rangeUnaffected {
		return "", MissInstalledPastFix
	}

	best, matched, sawPreRelease := minFixAcrossAffected(record.Affected, pkg, installed, installedOk, true)

	preRelease := false
	if best == "" {
		switch {
		case !matched:
			return "", MissPackageNotListed
		case sawPreRelease:
			best, _, _ = minFixAcrossAffected(record.Affected, pkg, installed, installedOk, false)
			preRelease = true
		default:
			return "", installedFixStatus(record.Affected, pkg, installed, installedOk)
		}
	}

	if pkg.typ == purlTypeMaven && !preRelease {
		best = matchClassifier(best, pkg.version)
	}
	if pkg.typ == purlTypeGolang && strings.HasPrefix(pkg.version, "v") && !strings.HasPrefix(best, "v") {
		best = "v" + best
	}
	return best, MissNone
}

type fixCandidate struct {
	raw     string
	version version
	parsed  bool
}

func (c fixCandidate) found() bool { return c.raw != "" }

// replaces compares parsed fixes by version and prefers them over unparseable ones such as GIT commits.
func (c fixCandidate) replaces(best fixCandidate) bool {
	switch {
	case !best.found():
		return true
	case c.parsed && best.parsed:
		return c.version.LT(best.version)
	default:
		return c.parsed && !best.parsed
	}
}

func minFixAcrossAffected(affected []Affected, pkg purl, installed version, installedOk, skipPreRelease bool) (string, bool, bool) {
	var best fixCandidate
	var matched, sawPreRelease bool

	for _, a := range affected {
		if !matchesPackage(a, pkg) {
			continue
		}
		matched = true
		candidate, skippedPreRelease := minFixFromRanges(a.Ranges, pkg.typ, installed, installedOk, skipPreRelease)
		sawPreRelease = sawPreRelease || skippedPreRelease
		if candidate.found() && candidate.replaces(best) {
			best = candidate
		}
	}
	return best.raw, matched, sawPreRelease
}

// minFixFromRanges returns the smallest fix version strictly greater than installed, preferring SEMVER > ECOSYSTEM, and GIT only when neither is present.
func minFixFromRanges(ranges []Range, typ string, installed version, installedOk, skipPreRelease bool) (fixCandidate, bool) {
	var skippedPreRelease bool
	for _, rangeType := range []string{rangeTypeSemver, rangeTypeEcosystem} {
		best, skipped := minFixFromRangeType(ranges, typ, rangeType, installed, installedOk, skipPreRelease)
		skippedPreRelease = skippedPreRelease || skipped
		if best.found() {
			return best, skippedPreRelease
		}
	}
	if slices.ContainsFunc(ranges, isComparable) {
		return fixCandidate{}, skippedPreRelease
	}
	return firstGitFix(ranges), skippedPreRelease
}

// firstGitFix returns a GIT fixed commit unparsed: commit hashes have no release order, even when they start with a digit.
func firstGitFix(ranges []Range) fixCandidate {
	for _, r := range ranges {
		if r.Type != rangeTypeGit {
			continue
		}
		for _, e := range r.Events {
			if e.Fixed != "" {
				return fixCandidate{raw: e.Fixed}
			}
		}
	}
	return fixCandidate{}
}

func minFixFromRangeType(ranges []Range, typ, rangeType string, installed version, installedOk, skipPreRelease bool) (fixCandidate, bool) {
	var best fixCandidate
	var skippedPreRelease bool

	for _, r := range ranges {
		if r.Type != rangeType {
			continue
		}
		for _, e := range r.Events {
			if e.Fixed == "" {
				continue
			}
			fixed, fixedOk := parseVersion(typ, e.Fixed)
			if installedOk && fixedOk && !fixed.GT(installed) {
				continue
			}
			if skipPreRelease && isPreReleaseFix(typ, e.Fixed) {
				skippedPreRelease = true
				continue
			}
			candidate := fixCandidate{raw: e.Fixed, version: fixed, parsed: fixedOk}
			if candidate.replaces(best) {
				best = candidate
			}
		}
	}
	return best, skippedPreRelease
}

const (
	rangeTypeSemver    = "SEMVER"
	rangeTypeEcosystem = "ECOSYSTEM"
	rangeTypeGit       = "GIT"
)

func matchesPackage(a Affected, pkg purl) bool {
	other, ok := parsePurl(a.Package.Purl)
	return ok && other.samePackage(pkg)
}

func isComparable(r Range) bool {
	return r.Type == rangeTypeSemver || r.Type == rangeTypeEcosystem
}

func hasFixBound(r Range) bool {
	return slices.ContainsFunc(r.Events, hasEnd)
}

func packageRanges(affected []Affected, pkg purl) []Range {
	var ranges []Range
	for _, a := range affected {
		if matchesPackage(a, pkg) {
			ranges = append(ranges, a.Ranges...)
		}
	}
	return ranges
}

func installedFixStatus(affected []Affected, pkg purl, installed version, installedOk bool) MissReason {
	ranges := packageRanges(affected, pkg)
	if !slices.ContainsFunc(ranges, hasFixBound) {
		return MissNoFixUpstream
	}
	switch installedState(affected, pkg, installed, installedOk) {
	case rangeAffected:
		return MissNoFixUpstream
	case rangeUnaffected:
		return MissInstalledPastFix
	default:
		return MissUnknown
	}
}

// installedState treats an installed version listed in affected.versions as affected before consulting the ranges.
func installedState(affected []Affected, pkg purl, installed version, installedOk bool) membership {
	if explicitlyAffected(affected, pkg, installed, installedOk) {
		return rangeAffected
	}
	if !installedOk {
		return rangeUnknown
	}
	return installedMembership(packageRanges(affected, pkg), pkg.typ, installed)
}

func explicitlyAffected(affected []Affected, pkg purl, installed version, installedOk bool) bool {
	for _, a := range affected {
		if !matchesPackage(a, pkg) {
			continue
		}
		for _, raw := range a.Versions {
			if raw == pkg.version {
				return true
			}
			listed, ok := parseVersion(pkg.typ, raw)
			if ok && installedOk && listed.compare(installed) == 0 {
				return true
			}
		}
	}
	return false
}

type membership uint8

const (
	rangeUnknown membership = iota
	rangeNotIntroduced
	rangeUnaffected
	rangeAffected
)

// installedMembership combines all comparable ranges: affected anywhere wins, then unknown, and past a fix counts only when no range is unknown.
func installedMembership(ranges []Range, typ string, installed version) membership {
	var sawUnknown, sawPastFix bool
	for _, r := range ranges {
		if !isComparable(r) {
			continue
		}
		switch rangeMembership(r.Events, typ, installed) {
		case rangeAffected:
			return rangeAffected
		case rangeUnknown:
			sawUnknown = true
		case rangeUnaffected:
			sawPastFix = true
		}
	}
	if sawPastFix && !sawUnknown {
		return rangeUnaffected
	}
	return rangeUnknown
}

func rangeMembership(events []Event, typ string, installed version) membership {
	intervals, ok := parseIntervals(events, typ)
	if !ok {
		return rangeUnknown
	}
	pastFix := false
	for _, i := range intervals {
		if i.contains(installed) {
			return rangeAffected
		}
		if i.endsBefore(installed) {
			pastFix = true
		}
	}
	if pastFix {
		return rangeUnaffected
	}
	return rangeNotIntroduced
}

type interval struct {
	start         version
	fromBeginning bool
	end           version
	open          bool
	endInclusive  bool
}

func (i interval) contains(v version) bool {
	if !i.fromBeginning && v.LT(i.start) {
		return false
	}
	return i.open || !i.endsBefore(v)
}

func (i interval) endsBefore(v version) bool {
	switch {
	case i.open:
		return false
	case i.endInclusive:
		return v.GT(i.end)
	default:
		return !v.LT(i.end)
	}
}

func parseIntervals(events []Event, typ string) ([]interval, bool) {
	var intervals []interval
	var current *interval
	for _, e := range events {
		switch {
		case isAmbiguous(e):
			return nil, false
		case e.Introduced != "":
			if current != nil {
				return nil, false
			}
			start, ok := parseIntroduced(typ, e.Introduced)
			if !ok {
				return nil, false
			}
			current = &start
		case hasEnd(e):
			if current == nil {
				return nil, false
			}
			if !current.close(typ, e) {
				return nil, false
			}
			intervals = append(intervals, *current)
			current = nil
		}
	}
	if current != nil {
		intervals = append(intervals, *current)
	}
	return intervals, true
}

func (i *interval) close(typ string, e Event) bool {
	raw, inclusive := e.Fixed, false
	if e.LastAffected != "" {
		raw, inclusive = e.LastAffected, true
	}
	end, ok := parseVersion(typ, raw)
	if !ok {
		return false
	}
	i.end, i.open, i.endInclusive = end, false, inclusive
	return true
}

func hasEnd(e Event) bool {
	return e.Fixed != "" || e.LastAffected != ""
}

func isAmbiguous(e Event) bool {
	return e.Limit != "" || (e.Introduced != "" && hasEnd(e)) || (e.Fixed != "" && e.LastAffected != "")
}

func parseIntroduced(typ, raw string) (interval, bool) {
	if raw == "0" {
		return interval{fromBeginning: true, open: true}, true
	}
	start, ok := parseVersion(typ, raw)
	return interval{start: start, open: true}, ok
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

type version struct {
	semantic.Version
}

func (v version) compare(o version) int {
	c, _ := v.Compare(o.Version)
	return c
}

func (v version) GT(o version) bool { return v.compare(o) > 0 }
func (v version) LT(o version) bool { return v.compare(o) < 0 }

// parseVersion orders versions by the purl type's OSV ecosystem rules.
func parseVersion(typ, raw string) (version, bool) {
	if !startsWithDigit.MatchString(raw) {
		return version{}, false
	}
	ecosystem, known := osvEcosystems[typ]
	if !known {
		return version{semantic.ParseSemverVersion(raw)}, true
	}
	v, err := semantic.Parse(withoutRuntimeClassifier(typ, raw), ecosystem)
	return version{v}, err == nil
}

var (
	startsWithDigit    = regexp.MustCompile(`^v?\d`)
	classifierSuffix   = regexp.MustCompile(`-([A-Za-z][A-Za-z0-9]*)$`)
	aliasHintSeparator = regexp.MustCompile(`[\s,]+`)
)
