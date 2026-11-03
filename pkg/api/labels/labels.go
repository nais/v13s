package labels

import "strings"

func IsPlatformLabel(key, value string) bool {
	switch key {
	case "app", "team", "euthanaisa.nais.io/kill-after":
		return true
	case "app.kubernetes.io/managed-by":
		return value == "console"
	}
	return strings.Contains(key, "nais.io/")
}
