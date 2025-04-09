package k8s

import (
	"strings"

	nais "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

var _ cache.ResourceEventHandler = &workloadHandler{}

type workloadHandler struct {
	cluster string
	log     logrus.FieldLogger
}

func newWorkloadHandler(cluster string, log logrus.FieldLogger) *workloadHandler {
	return &workloadHandler{
		cluster: cluster,
		log:     log,
	}
}

func (w workloadHandler) OnAdd(obj any, _ bool) {
	o := w.convert(obj)
	workloads := extractWorkloads(w.cluster, o)
	for _, workload := range workloads {
		w.log.WithField("workload_type", workload.Type).Debugf("adding workload name: %s", workload.Name)
	}
}

func (w workloadHandler) OnUpdate(oldObj, newObj any) {
	ou := w.convert(oldObj)
	nu := w.convert(newObj)
	oldWorkloads := extractWorkloads(w.cluster, ou)
	newWorkloads := extractWorkloads(w.cluster, nu)
	if hasChanged(oldWorkloads, newWorkloads) {
		w.log.Debug("OnUpdate workloads changed")
	} else {
		w.log.Debug("OnUpdate workloads not changed")
	}

}

func (w workloadHandler) OnDelete(obj any) {
	a, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = a.Obj
	}

	o := w.convert(obj)
	workloads := extractWorkloads(w.cluster, o)
	for _, workload := range workloads {
		w.log.WithField("workload_type", workload.Type).Debugf("deleting workload name: %s", workload.Name)
	}
}

func (w workloadHandler) convert(obj any) *unstructured.Unstructured {
	o, ok := obj.(*unstructured.Unstructured)
	if !ok {
		w.log.WithFields(logrus.Fields{
			"kind":          o.GetKind(),
			"resource_name": o.GetName(),
		}).Warn("could not convert to unstructured")
		return nil
	}
	return o
}

func hasChanged(old []*model.Workload, new []*model.Workload) bool {
	if len(old) != len(new) {
		return true
	}
	for _, cn := range new {
		found := false
		for _, co := range old {
			if co.Equal(cn) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func extractWorkloads(cluster string, obj *unstructured.Unstructured) []*model.Workload {
	ret := make([]*model.Workload, 0)
	if obj == nil {
		return ret
	}

	switch obj.GetKind() {
	case "Deployment":
		var deployment *v1.Deployment
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &deployment)
		if err != nil {
			return ret
		}

		for _, c := range deployment.Spec.Template.Spec.Containers {
			name, tag := imageNameTag(c.Image)
			wType := model.WorkloadTypeDeployment
			for _, ref := range deployment.OwnerReferences {
				if ref.Kind == "Application" && ref.APIVersion == "nais.io/v1alpha1" {
					wType = model.WorkloadTypeApp
				}
			}

			ret = append(ret, &model.Workload{
				Name:      setWorkloadName(c.Name, deployment.GetName()),
				Namespace: deployment.GetNamespace(),
				Cluster:   cluster,
				Type:      wType,
				ImageName: name,
				ImageTag:  tag,
			})
		}
	case "Naisjob":
		var job *nais.Naisjob
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &job)
		if err != nil {
			return ret
		}
		name, tag := imageNameTag(job.Spec.Image)
		w := &model.Workload{
			Cluster:   cluster,
			Name:      jobName(job),
			Namespace: job.GetNamespace(),
			Type:      model.WorkloadTypeJob,
			ImageName: name,
			ImageTag:  tag,
		}
		if job.Status.DeploymentRolloutStatus == "complete" {
			w.Status.LastSuccessful = true
		}
		ret = append(ret, w)
	}
	return ret
}

// A workload can have multiple containers, we need to set the workload name to the container name
// if the container name is different from the workload name (other container) we now create each separate workload
// for each container, probably we should reference the main workload with its containers.
// TODO: Potentially an issue, ok for naiserator created workloads
func setWorkloadName(containerName, workloadName string) string {
	if containerName == workloadName {
		return workloadName
	}
	return containerName
}

func jobName(job *nais.Naisjob) string {
	workloadName := job.Labels["app"]
	if workloadName != "" {
		return workloadName
	}

	return job.GetName()
}

func imageNameTag(image string) (string, string) {
	parts := strings.Split(image, ":")
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}
