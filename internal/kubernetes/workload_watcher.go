package kubernetes

import (
	"context"
	"github.com/nais/v13s/internal/manager"
	"github.com/nais/v13s/internal/model"

	nais "github.com/nais/liberator/pkg/apis/nais.io/v1"
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
	workload := model.AsWorkload(cluster, obj)
	if workload == nil {
		w.log.Warnf("object type not supported for workload: %T", obj)
		return
	}
	if err := manager.AddOrUpdateWorkload(ctx, workload); err != nil {
		w.log.WithError(err).Error("add or update workload with manager")
		return
	}
}

func (w *WorkloadWatcher) remove(ctx context.Context, cluster string, obj any) {
	workload := model.AsWorkload(cluster, obj)
	if workload == nil {
		w.log.Warnf("object type not supported for workload: %T", obj)
		return
	}
	if err := manager.DeleteWorkload(ctx, workload); err != nil {
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
