package grpcvulnerabilities

import (
	"encoding/json"

	labelpolicy "github.com/nais/v13s/pkg/api/labels"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/validate/content"
)

func summaryLabelParameters(labels []*vulnerabilities.LabelFilter) ([]byte, error) {
	for _, label := range labels {
		if label == nil {
			return nil, status.Error(codes.InvalidArgument, "label filter is required")
		}
		if err := validateUserLabelKey(label.GetKey(), label.GetValue()); err != nil {
			return nil, err
		}
		if label.Value != nil && len(content.IsLabelValue(label.GetValue())) > 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid label value")
		}
	}
	if len(labels) == 0 {
		return nil, nil
	}
	return json.Marshal(labels)
}

func validateUserLabelKey(key, value string) error {
	if len(content.IsLabelKey(key)) > 0 {
		return status.Error(codes.InvalidArgument, "invalid label key")
	}
	if labelpolicy.IsPlatformLabel(key, value) {
		return status.Error(codes.InvalidArgument, "label key is reserved")
	}
	return nil
}
