package model

import (
	"fmt"
)

type WorkloadType string

const (
	WorkloadTypeApp        WorkloadType = "app"
	WorkloadTypeJob        WorkloadType = "job"
	WorkloadTypePlatform   WorkloadType = "platform"
	WorkloadTypeDeployment WorkloadType = "deployment"
)

type Workload struct {
	Cluster   string
	Namespace string
	Type      WorkloadType
	Name      string
	ImageName string
	ImageTag  string
	Status    Status
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
		w.ImageTag == other.ImageTag
}

func (w *Workload) String() string {
	return fmt.Sprintf("%s/%s/%s/%s/%s:%s", "todo", w.Namespace, w.Type, w.Name, w.ImageName, w.ImageTag)
}
