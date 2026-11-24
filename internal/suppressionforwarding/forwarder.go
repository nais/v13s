package suppressionforwarding

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/suppressionforwarding/v0sapi"
	"github.com/package-url/packageurl-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Outcome string

const (
	OutcomeApplied                Outcome = "applied"
	OutcomeNoWorkloads            Outcome = "no_workloads"
	OutcomeUnknownVulnerability   Outcome = "unknown_vulnerability"
	OutcomeAmbiguousVulnerability Outcome = "ambiguous_vulnerability"
	OutcomeConflictingAssessments Outcome = "conflicting_assessments"
	OutcomeUnsupportedReason      Outcome = "unsupported_reason"
	OutcomeIncompleteAssessment   Outcome = "incomplete_assessment"
	OutcomeUnsupportedPackage     Outcome = "unsupported_package"
	OutcomeNoSourceRows           Outcome = "no_source_rows"
	OutcomeSourceReadFailed       Outcome = "source_read_failed"
	OutcomeAdvisoryLookupFailed   Outcome = "advisory_lookup_failed"
	OutcomeFailed                 Outcome = "failed"
)

type Change struct {
	ImageName        string
	Package          string
	VulnerabilityIDs []string
}

type SourceReader interface {
	ListSuppressedVulnerabilitiesForImage(ctx context.Context, imageName string) ([]*sql.SuppressedVulnerability, error)
}

type Forwarder struct {
	client   v0sapi.SuppressionServiceClient
	timeout  time.Duration
	upstream *Upstream
	log      logrus.FieldLogger
	now      func() time.Time
}

func New(conn grpc.ClientConnInterface, timeout time.Duration, upstream *Upstream, log logrus.FieldLogger) *Forwarder {
	return &Forwarder{client: v0sapi.NewSuppressionServiceClient(conn), timeout: timeout, upstream: upstream, log: log, now: time.Now}
}

type Expectation struct {
	PackageKey      string
	SourceUpdatedAt time.Time
	Assessment      *v0sapi.V13SAssessment
	TargetIDs       []string
}

func Expect(ctx context.Context, source SourceReader, upstream *Upstream, change Change) (Expectation, Outcome) {
	var exp Expectation
	key, err := PackageKey(change.Package)
	if err != nil {
		return exp, OutcomeUnsupportedPackage
	}
	exp.PackageKey = key
	rows, err := source.ListSuppressedVulnerabilitiesForImage(ctx, change.ImageName)
	if err != nil {
		return exp, OutcomeSourceReadFailed
	}
	group := groupRows(rows, key, change.VulnerabilityIDs)
	if len(group) == 0 {
		return exp, OutcomeNoSourceRows
	}
	exp.SourceUpdatedAt = latestUpdate(group)
	assessment, blocked := assess(group, exp.SourceUpdatedAt)
	if blocked != "" {
		return exp, blocked
	}
	exp.Assessment = assessment
	exp.TargetIDs = change.VulnerabilityIDs
	if upstream != nil {
		extra, err := upstream.IDs(ctx, change.VulnerabilityIDs, key)
		if err != nil {
			return exp, OutcomeAdvisoryLookupFailed
		}
		exp.TargetIDs = slices.Concat(change.VulnerabilityIDs, extra)
	}
	return exp, ""
}

func (f *Forwarder) Forward(ctx context.Context, source SourceReader, change Change) {
	if f == nil || len(change.VulnerabilityIDs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), f.timeout)
	defer cancel()

	log := f.log.WithFields(logrus.Fields{
		"image_name":       change.ImageName,
		"vulnerability_id": change.VulnerabilityIDs[0],
	})
	exp, blocked := Expect(ctx, source, f.upstream, change)
	switch {
	case exp.PackageKey == "":
		log = log.WithField("package", change.Package)
	case exp.SourceUpdatedAt.IsZero():
		log = log.WithField("package_key", exp.PackageKey)
	default:
		log = log.WithFields(logrus.Fields{"package_key": exp.PackageKey, "source_updated_at": exp.SourceUpdatedAt})
	}
	if blocked != "" {
		f.record(log, blocked)
		return
	}
	resp, err := f.client.ForwardV13SSuppression(ctx, &v0sapi.ForwardV13SSuppressionRequest{
		ImageName:        change.ImageName,
		Package:          exp.PackageKey,
		VulnerabilityIds: exp.TargetIDs,
		Assessment:       exp.Assessment,
	})
	if err != nil {
		f.record(log.WithField("grpc_code", status.Code(err).String()), OutcomeFailed)
		return
	}
	outcome := outcomeFromV0s(resp.GetOutcome())
	if outcome == OutcomeApplied {
		log = log.WithFields(logrus.Fields{
			"applied":         resp.GetApplied(),
			"removed":         resp.GetRemoved(),
			"acknowledged_at": f.now().UTC(),
		})
	}
	f.record(log, outcome)
}

func (f *Forwarder) record(log logrus.FieldLogger, outcome Outcome) {
	metrics.RecordSuppressionForwardOutcome(string(outcome))
	log = log.WithField("outcome", outcome)
	if outcome == OutcomeApplied {
		log.Info("forwarded suppression to v0s")
		return
	}
	log.Warn("suppression not forwarded to v0s")
}

func PackageKey(raw string) (string, error) {
	p, err := packageurl.FromString(raw)
	if err != nil {
		return "", err
	}
	p.Version, p.Qualifiers, p.Subpath = "", nil, ""
	return p.ToString(), nil
}

func groupRows(rows []*sql.SuppressedVulnerability, key string, ids []string) []*sql.SuppressedVulnerability {
	var group []*sql.SuppressedVulnerability
	for _, row := range rows {
		if !slices.Contains(ids, row.CveID) {
			continue
		}
		if k, err := PackageKey(row.Package); err == nil && k == key {
			group = append(group, row)
		}
	}
	return group
}

func latestUpdate(rows []*sql.SuppressedVulnerability) time.Time {
	var latest time.Time
	for _, row := range rows {
		if row.UpdatedAt.Valid && row.UpdatedAt.Time.After(latest) {
			latest = row.UpdatedAt.Time
		}
	}
	return latest
}

func assess(rows []*sql.SuppressedVulnerability, updatedAt time.Time) (*v0sapi.V13SAssessment, Outcome) {
	first := rows[0]
	for _, row := range rows[1:] {
		if row.Suppressed != first.Suppressed {
			return nil, OutcomeConflictingAssessments
		}
	}
	if !first.Suppressed {
		return nil, ""
	}
	state := stateFor(first.Reason)
	for _, row := range rows[1:] {
		if stateFor(row.Reason) != state || row.SuppressedBy != first.SuppressedBy {
			return nil, OutcomeConflictingAssessments
		}
	}
	detail := mergeReasonTexts(rows)
	switch {
	case state == v0sapi.SuppressionState_SUPPRESSION_STATE_UNSPECIFIED:
		return nil, OutcomeUnsupportedReason
	case detail == "" || first.SuppressedBy == "":
		return nil, OutcomeIncompleteAssessment
	}
	return &v0sapi.V13SAssessment{
		State:     state,
		Detail:    detail,
		UpdatedBy: first.SuppressedBy,
		UpdatedAt: timestamppb.New(updatedAt),
	}, ""
}

type reasonText struct {
	text     string
	versions []string
	latest   time.Time
}

func mergeReasonTexts(rows []*sql.SuppressedVulnerability) string {
	var texts []*reasonText
	for _, row := range rows {
		if row.ReasonText == "" {
			continue
		}
		i := slices.IndexFunc(texts, func(t *reasonText) bool { return t.text == row.ReasonText })
		if i < 0 {
			texts = append(texts, &reasonText{text: row.ReasonText})
			i = len(texts) - 1
		}
		t := texts[i]
		if v := packageVersion(row.Package); !slices.Contains(t.versions, v) {
			t.versions = append(t.versions, v)
		}
		if row.UpdatedAt.Time.After(t.latest) {
			t.latest = row.UpdatedAt.Time
		}
	}
	switch len(texts) {
	case 0:
		return ""
	case 1:
		return texts[0].text
	}
	slices.SortFunc(texts, func(a, b *reasonText) int {
		if c := b.latest.Compare(a.latest); c != 0 {
			return c
		}
		return strings.Compare(a.text, b.text)
	})
	parts := make([]string, 0, len(texts))
	for _, t := range texts {
		slices.Sort(t.versions)
		parts = append(parts, strings.Join(t.versions, ", ")+": "+t.text)
	}
	return strings.Join(parts, "\n\n")
}

func packageVersion(raw string) string {
	if p, err := packageurl.FromString(raw); err == nil && p.Version != "" {
		return p.Version
	}
	return "unversioned"
}

func stateFor(reason sql.VulnerabilitySuppressReason) v0sapi.SuppressionState {
	switch reason {
	case sql.VulnerabilitySuppressReasonNotAffected:
		return v0sapi.SuppressionState_SUPPRESSION_STATE_NOT_AFFECTED
	case sql.VulnerabilitySuppressReasonFalsePositive:
		return v0sapi.SuppressionState_SUPPRESSION_STATE_FALSE_POSITIVE
	case sql.VulnerabilitySuppressReasonInTriage, sql.VulnerabilitySuppressReasonResolved:
		return v0sapi.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK
	}
	return v0sapi.SuppressionState_SUPPRESSION_STATE_UNSPECIFIED
}

func outcomeFromV0s(o v0sapi.ForwardOutcome) Outcome {
	switch o {
	case v0sapi.ForwardOutcome_FORWARD_OUTCOME_APPLIED:
		return OutcomeApplied
	case v0sapi.ForwardOutcome_FORWARD_OUTCOME_NO_WORKLOADS:
		return OutcomeNoWorkloads
	case v0sapi.ForwardOutcome_FORWARD_OUTCOME_UNKNOWN_VULNERABILITY:
		return OutcomeUnknownVulnerability
	case v0sapi.ForwardOutcome_FORWARD_OUTCOME_AMBIGUOUS_VULNERABILITY:
		return OutcomeAmbiguousVulnerability
	}
	return OutcomeFailed
}
