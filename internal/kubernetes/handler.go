package kubernetes

import (
	"strings"

	nais "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

var _ cache.ResourceEventHandler = &eventHandler{}

type eventHandler struct {
	cluster    string
	eventQueue *WorkloadEventQueue
	log        logrus.FieldLogger
}

type WorkloadEventQueue struct {
	Updated chan *model.Workload
	Deleted chan *model.Workload
}

func newEventHandler(cluster string, eventQueue *WorkloadEventQueue, log logrus.FieldLogger) *eventHandler {
	return &eventHandler{
		cluster:    cluster,
		eventQueue: eventQueue,
		log:        log,
	}
}

func (w eventHandler) OnAdd(obj any, _ bool) {
	o := w.convert(obj)

	workloads := extractWorkloads(w.cluster, o)
	for _, workload := range workloads {
		w.log.WithField("workload_type", workload.Type).Debugf("adding workload name: %s", workload.Name)
		w.eventQueue.Updated <- workload
	}
}

func (w eventHandler) OnUpdate(oldObj, newObj any) {
	ou := w.convert(oldObj)
	nu := w.convert(newObj)
	oldWorkloads := extractWorkloads(w.cluster, ou)
	newWorkloads := extractWorkloads(w.cluster, nu)
	if hasChanged(oldWorkloads, newWorkloads) {
		for _, workload := range newWorkloads {
			w.log.WithField("workload_type", workload.Type).Debugf("updating workload name: %s", workload.Name)
			w.eventQueue.Updated <- workload
		}
	} else {
		w.log.Debug("OnUpdate workloads not changed")
	}
}

func (w eventHandler) OnDelete(obj any) {
	a, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = a.Obj
	}

	o := w.convert(obj)
	workloads := extractWorkloads(w.cluster, o)
	for _, workload := range workloads {
		w.log.WithField("workload_type", workload.Type).Debugf("deleting workload name: %s", workload.Name)
		w.eventQueue.Deleted <- workload
	}
}

func (w eventHandler) convert(obj any) *unstructured.Unstructured {
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
			wType := getWorkloadType(deployment, c)

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

func getWorkloadType(deployment *v1.Deployment, container corev1.Container) model.WorkloadType {
	isPlatformImage := collections.AnyMatch([]string{
		"gcr.io/cloud-sql-connectors/cloud-sql-proxy",
		"docker.io/devopsfaith/krakend",
		"europe-north1-docker.pkg.dev/nais-io/nais/images/elector",
	}, func(e string) bool {
		return strings.HasPrefix(container.Image, e) || container.Name == "wonderwall"
	})

	wType := model.WorkloadTypeDeployment
	for _, ref := range deployment.OwnerReferences {
		if ref.Kind == "Application" && ref.APIVersion == "nais.io/v1alpha1" {
			wType = model.WorkloadTypeApp
		}
	}

	if isPlatformImage {
		wType = model.WorkloadTypePlatform
	}
	return wType
}

// A workload can have multiple containers, we need to set the workload name to the container name
// if the container name is different from the workload name (other container) we now create each separate workload
// for each container, probably we should reference the main workload with its containers.
// TODO: Potentially an issue, ok for naiserator created workloads
func setWorkloadName(containerName, workloadName string) string {
	if containerName == workloadName {
		return workloadName
	}
	return workloadName + "-" + containerName
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
