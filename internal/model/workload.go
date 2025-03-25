package model

import (
	"fmt"
	nais "github.com/nais/liberator/pkg/apis/nais.io/v1"
	v1 "k8s.io/api/apps/v1"
)

type Workload struct {
	Cluster   string
	Name      string
	Namespace string
	Images    []Image
	Status    Status
	Type      string
	Metadata  map[string]string
}

type Image struct {
	Name          string
	ContainerName string
}

type Status struct {
	LastSuccessful bool
	ScaledDown     bool
}

func (w *Workload) String() string {
	return fmt.Sprintf("%s/%s/%s/%s/%v", "todo", w.Namespace, w.Type, w.Name, w.Images)

}

func AsWorkload(cluster string, obj any) *Workload {
	if obj == nil {
		return nil
	}

	switch obj := obj.(type) {
	case *v1.Deployment:
		deployment := obj
		images := make([]Image, 0)
		for _, c := range deployment.Spec.Template.Spec.Containers {
			images = append(images, Image{
				Name:          c.Image,
				ContainerName: c.Name,
			})
		}
		return &Workload{
			Cluster:   cluster,
			Name:      deployment.GetName(),
			Namespace: deployment.GetNamespace(),
			// TODO: consider using some sort of checking if the workload has labels identifying
			// TODO: an "nais application", and if so, set the type to "app" otherwise to its original type, deployment etc.
			Type:   "app",
			Images: images,
		}
	case *nais.Naisjob:
		job := obj
		workload := &Workload{
			Cluster:   cluster,
			Name:      jobName(job),
			Namespace: job.GetNamespace(),
			Type:      "job",
			Images:    []Image{{Name: job.Spec.Image, ContainerName: jobName(job)}},
		}

		if job.Status.DeploymentRolloutStatus == "complete" {
			workload.Status.LastSuccessful = true
		}
		return workload
	}
	return nil
}

func jobName(job *nais.Naisjob) string {
	workloadName := job.Labels["app"]
	if workloadName != "" {
		return workloadName
	}

	return job.GetName()
}
