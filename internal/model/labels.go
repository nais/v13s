package model

import labelpolicy "github.com/nais/v13s/pkg/api/labels"

func UserLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		if !labelpolicy.IsPlatformLabel(key, value) {
			result[key] = value
		}
	}
	return result
}
