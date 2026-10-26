package labels

import "testing"

type platformLabelCase struct {
	key, value string
	hidden     bool
}

func TestIsPlatformLabel(t *testing.T) {
	for _, test := range []platformLabelCase{
		{"owner", "", false},
		{"example.org/group", "team", false},
		{"mynais.io/internal", "yes", false},
		{"foo.notnais.io/internal", "yes", false},
		{"app", "demo", true},
		{"team", "demo", true},
		{"nais.io/internal", "yes", true},
		{"custom.nais.io/internal", "yes", true},
		{"euthanaisa.nais.io/kill-after", "tomorrow", true},
		{"app.kubernetes.io/managed-by", "console", true},
		{"app.kubernetes.io/managed-by", "helm", false},
		{"app.kubernetes.io/managed-by", "", false},
	} {
		t.Run(test.key+"="+test.value, func(t *testing.T) {
			if got := IsPlatformLabel(test.key, test.value); got != test.hidden {
				t.Errorf("IsPlatformLabel(%q, %q) = %v, want %v", test.key, test.value, got, test.hidden)
			}
		})
	}
}
