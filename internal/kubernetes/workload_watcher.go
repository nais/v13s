package kubernetes

import (
	"context"
	"strings"

	nais "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/v13s/internal/manager"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/apps/v1"
)

type WorkloadWatcher struct {
	mgr *Manager
	log *logrus.Entry
}

func NewWorkloadWatcher(ctx context.Context, mgr *Manager, log *logrus.Entry) *WorkloadWatcher {
	w := &WorkloadWatcher{
		mgr: mgr,
		log: log,
	}

	w.addWatcherFuncs(ctx)
	return w
}

func (w *WorkloadWatcher) addOrUpdate(ctx context.Context, cluster string, obj any) {
	workloads := getWorkloads(cluster, obj)
	if len(workloads) == 0 {
		w.log.Warnf("object type not supported for workload: %T", obj)
		return
	}
	if err := manager.AddOrUpdateWorkloads(ctx, workloads...); err != nil {
		w.log.WithError(err).Error("add or update workload with manager")
		return
	}
}

func (w *WorkloadWatcher) remove(ctx context.Context, cluster string, obj any) {
	workloads := getWorkloads(cluster, obj)
	if len(workloads) == 0 {
		w.log.Warnf("object type not supported for workload: %T", obj)
		return
	}
	if err := manager.DeleteWorkloads(ctx, workloads...); err != nil {
		w.log.WithError(err).Error("delete workload with manager")
		return
	}
}

func (w *WorkloadWatcher) addWatcherFuncs(ctx context.Context) {
	d := Watch(w.mgr, &v1.Deployment{})
	d.OnAdd(func(cluster string, obj *v1.Deployment) {
		w.addOrUpdate(ctx, cluster, obj)
	})
	d.OnUpdate(func(cluster string, obj *v1.Deployment) {
		w.addOrUpdate(ctx, cluster, obj)
	})
	d.OnRemove(func(cluster string, obj *v1.Deployment) {
		w.remove(ctx, cluster, obj)
	})
	d.Start(ctx)

	j := Watch(w.mgr, &nais.Naisjob{})
	j.OnAdd(func(cluster string, obj *nais.Naisjob) {
		w.addOrUpdate(ctx, cluster, obj)
	})
	j.OnUpdate(func(cluster string, obj *nais.Naisjob) {
		w.addOrUpdate(ctx, cluster, obj)
	})
	j.OnRemove(func(cluster string, obj *nais.Naisjob) {
		w.remove(ctx, cluster, obj)
	})
	j.Start(ctx)
}

func getWorkloads(cluster string, obj any) []*model.Workload {
	ret := make([]*model.Workload, 0)
	if obj == nil {
		return ret
	}

	switch obj := obj.(type) {
	case *v1.Deployment:
		deployment := obj
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
	case *nais.Naisjob:
		job := obj
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
