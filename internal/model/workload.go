package model

import (
	"fmt"
	"maps"
)

type WorkloadType string

const (
	WorkloadTypeApp        WorkloadType = "app"
	WorkloadTypeJob        WorkloadType = "job"
	WorkloadTypePlatform   WorkloadType = "platform"
	WorkloadTypeDeployment WorkloadType = "deployment"
)

type Workload struct {
	Cluster         string
	Namespace       string
	Type            WorkloadType
	Name            string
	ImageName       string
	ImageTag        string
	Status          Status
	Labels          map[string]string
	ResourceVersion string
}

type Status struct {
	LastSuccessful bool
	ScaledDown     bool
}

func (w *Workload) Equal(other *Workload) bool {
	return w.Name == other.Name &&
		w.Namespace == other.Namespace &&
		w.Type == other.Type &&
		w.ImageName == other.ImageName &&
		w.ImageTag == other.ImageTag &&
		maps.Equal(w.Labels, other.Labels)
}

func (w *Workload) String() string {
	return fmt.Sprintf("%s/%s/%s/%s", w.Cluster, w.Namespace, w.Type, w.Name)
}
