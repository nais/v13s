package kubernetes

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func NewScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	funcs := []func(s *runtime.Scheme) error{
		corev1.AddToScheme,
	}

	for _, f := range funcs {
		if err := f(scheme); err != nil {
			return nil, err
		}
	}

	return scheme, nil
}
