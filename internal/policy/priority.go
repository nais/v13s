// Package policy evaluates CEL rules against vulnerability data, replacing
// the CASE WHEN in internal/database/queries/vulnerabilities.sql
// (UpdateCvePriority, UpdateCvePriorityForCves).
package policy

import (
	"fmt"

	"github.com/google/cel-go/cel"
)

// Priority mirrors the tiers stored on cve.priority.
const (
	PriorityHigh     int32 = 2
	PriorityElevated int32 = 3
	PriorityMonitor  int32 = 4
)

// PriorityInput is the data a priority rule evaluates against.
//
// EpssScore and EpssPercentile are plain float64, not *float64: the cve
// table's columns are nullable and the SQL version COALESCEs a null to 0.
// Callers must do the same conversion; the zero value here already matches.
type PriorityInput struct {
	Severity           int32
	EpssScore          float64
	EpssPercentile     float64
	HasKevEntry        bool
	KnownRansomwareUse bool

	// DeclaredHash is what the SBOM claims, RegistryHash is what the package
	// registry actually published. RegistryHash is "" until a resolver fills
	// it in; the rule below stays dormant until then.
	DeclaredHash string
	RegistryHash string
}

type priorityRule struct {
	name       string
	expression string
	tier       int32
	program    cel.Program
}

// defaultPriorityRules mirrors UpdateCvePriorityForCves rule for rule; keep
// the two in sync, priority_test.go checks them against the same cases.
var defaultPriorityRules = []*priorityRule{
	{
		name:       "component-hash-mismatch",
		expression: `registry_hash != "" && declared_hash != registry_hash`,
		tier:       PriorityHigh,
	},
	{
		name:       "kev-or-ransomware-or-high-epss",
		expression: `has_kev_entry || known_ransomware_use || epss_percentile >= 0.95 || epss_score >= 0.10`,
		tier:       PriorityHigh,
	},
	{
		name:       "critical-or-high-severity-with-elevated-epss",
		expression: `severity in [0, 1] && epss_percentile >= 0.90`, // 0 = CRITICAL, 1 = HIGH
		tier:       PriorityElevated,
	},
}

// PriorityEvaluator compiles a rule set once and evaluates it against many
// inputs without recompiling per call.
type PriorityEvaluator struct {
	rules []*priorityRule
}

func NewPriorityEvaluator() (*PriorityEvaluator, error) {
	return newPriorityEvaluator(defaultPriorityRules)
}

func newPriorityEvaluator(rules []*priorityRule) (*PriorityEvaluator, error) {
	env, err := cel.NewEnv(
		cel.Variable("severity", cel.IntType),
		cel.Variable("epss_score", cel.DoubleType),
		cel.Variable("epss_percentile", cel.DoubleType),
		cel.Variable("has_kev_entry", cel.BoolType),
		cel.Variable("known_ransomware_use", cel.BoolType),
		cel.Variable("declared_hash", cel.StringType),
		cel.Variable("registry_hash", cel.StringType),
	)
	if err != nil {
		return nil, fmt.Errorf("building cel environment: %w", err)
	}

	compiled := make([]*priorityRule, 0, len(rules))
	for _, r := range rules {
		ast, issues := env.Compile(r.expression)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compiling rule %q: %w", r.name, issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("building program for rule %q: %w", r.name, err)
		}
		compiled = append(compiled, &priorityRule{
			name:       r.name,
			expression: r.expression,
			tier:       r.tier,
			program:    prg,
		})
	}

	return &PriorityEvaluator{rules: compiled}, nil
}

// Evaluate returns the tier of the first matching rule, or PriorityMonitor
// if none match.
func (e *PriorityEvaluator) Evaluate(input PriorityInput) (int32, error) {
	vars := map[string]any{
		"severity":             int64(input.Severity),
		"epss_score":           input.EpssScore,
		"epss_percentile":      input.EpssPercentile,
		"has_kev_entry":        input.HasKevEntry,
		"known_ransomware_use": input.KnownRansomwareUse,
		"declared_hash":        input.DeclaredHash,
		"registry_hash":        input.RegistryHash,
	}

	for _, rule := range e.rules {
		out, _, err := rule.program.Eval(vars)
		if err != nil {
			return 0, fmt.Errorf("evaluating rule %q: %w", rule.name, err)
		}
		matched, ok := out.Value().(bool)
		if !ok {
			return 0, fmt.Errorf("rule %q did not evaluate to a bool", rule.name)
		}
		if matched {
			return rule.tier, nil
		}
	}

	return PriorityMonitor, nil
}
