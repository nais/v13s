package policy

import "testing"

func TestPriorityEvaluator_MatchesSQLLogic(t *testing.T) {
	eval, err := NewPriorityEvaluator()
	if err != nil {
		t.Fatalf("NewPriorityEvaluator() error = %v", err)
	}

	tests := []struct {
		name  string
		input PriorityInput
		want  int32
	}{
		{
			name:  "zero value defaults to monitor",
			input: PriorityInput{},
			want:  PriorityMonitor,
		},
		{
			name:  "kev entry alone is high",
			input: PriorityInput{HasKevEntry: true},
			want:  PriorityHigh,
		},
		{
			name:  "known ransomware use alone is high",
			input: PriorityInput{KnownRansomwareUse: true},
			want:  PriorityHigh,
		},
		{
			name:  "epss percentile at the 0.95 boundary is high",
			input: PriorityInput{EpssPercentile: 0.95},
			want:  PriorityHigh,
		},
		{
			name:  "epss percentile just under 0.95 does not trigger the high-epss rule alone",
			input: PriorityInput{Severity: 2, EpssPercentile: 0.949999},
			want:  PriorityMonitor,
		},
		{
			name:  "epss score at the 0.10 boundary is high",
			input: PriorityInput{EpssScore: 0.10},
			want:  PriorityHigh,
		},
		{
			name:  "epss score just under 0.10 does not trigger the high-epss rule alone",
			input: PriorityInput{EpssScore: 0.099999},
			want:  PriorityMonitor,
		},
		{
			name:  "critical severity with epss percentile at the 0.90 boundary is elevated",
			input: PriorityInput{Severity: 0, EpssPercentile: 0.90},
			want:  PriorityElevated,
		},
		{
			name:  "high severity with epss percentile at the 0.90 boundary is elevated",
			input: PriorityInput{Severity: 1, EpssPercentile: 0.90},
			want:  PriorityElevated,
		},
		{
			name:  "critical severity with epss percentile just under 0.90 is monitor",
			input: PriorityInput{Severity: 0, EpssPercentile: 0.899999},
			want:  PriorityMonitor,
		},
		{
			name:  "medium severity with high epss percentile below the high-tier boundary is monitor",
			input: PriorityInput{Severity: 2, EpssPercentile: 0.90},
			want:  PriorityMonitor,
		},
		{
			name:  "medium severity with epss percentile at the high-tier boundary is still high",
			input: PriorityInput{Severity: 2, EpssPercentile: 0.95},
			want:  PriorityHigh,
		},
		{
			name:  "kev takes priority over an otherwise-monitor severity and epss combination",
			input: PriorityInput{Severity: 3, EpssPercentile: 0, EpssScore: 0, HasKevEntry: true},
			want:  PriorityHigh,
		},
		{
			name:  "declared hash alone, no registry hash yet, does not read as a mismatch",
			input: PriorityInput{Severity: 3, DeclaredHash: "abc123"},
			want:  PriorityMonitor,
		},
		{
			name:  "matching declared and registry hash is not a mismatch",
			input: PriorityInput{Severity: 3, DeclaredHash: "abc123", RegistryHash: "abc123"},
			want:  PriorityMonitor,
		},
		{
			name:  "differing declared and registry hash is high",
			input: PriorityInput{Severity: 3, DeclaredHash: "abc123", RegistryHash: "def456"},
			want:  PriorityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval.Evaluate(tt.input)
			if err != nil {
				t.Fatalf("Evaluate(%+v) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("Evaluate(%+v) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewPriorityEvaluator_CompilesOnce(t *testing.T) {
	eval, err := NewPriorityEvaluator()
	if err != nil {
		t.Fatalf("NewPriorityEvaluator() error = %v", err)
	}
	if len(eval.rules) != len(defaultPriorityRules) {
		t.Fatalf("got %d compiled rules, want %d", len(eval.rules), len(defaultPriorityRules))
	}
	for _, r := range eval.rules {
		if r.program == nil {
			t.Errorf("rule %q has no compiled program", r.name)
		}
	}
}
