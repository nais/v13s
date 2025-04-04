package model

import (
	"fmt"
)

type WorkloadType string

const (
	WorkloadTypeApp      WorkloadType = "app"
	WorkloadTypeJob      WorkloadType = "job"
	WorkloadTypePlatform WorkloadType = "platform"
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

func (w *Workload) String() string {
	return fmt.Sprintf("%s/%s/%s/%s/%s:%s", "todo", w.Namespace, w.Type, w.Name, w.ImageName, w.ImageTag)
}
