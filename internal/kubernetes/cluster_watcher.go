package kubernetes

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	_ "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

type Object interface {
	runtime.Object
	GetName() string
	GetNamespace() string
	GetLabels() map[string]string
}

type clusterWatcher[T Object] struct {
	manager       *clusterManager
	isRegistered  bool
	informer      informers.GenericInformer
	cluster       string
	watcher       *Watcher[T]
	log           logrus.FieldLogger
	converterFunc func(o *unstructured.Unstructured, environmentName string) (obj any, ok bool)
	gvr           schema.GroupVersionResource
}

func newClusterWatcher[T Object](mgr *clusterManager, cluster string, watcher *Watcher[T], obj T, settings *watcherSettings, log logrus.FieldLogger) (*clusterWatcher[T], schema.GroupVersionResource) {
	inf, gvr, err := mgr.createInformer(obj, settings.gvr, settings.filterLabelSelector)
	if err != nil {
		mgr.log.WithError(err).Error("creating informer")
		return &clusterWatcher[T]{
			manager:      mgr,
			isRegistered: false,
		}, gvr
	}

	w := &clusterWatcher[T]{
		manager:       mgr,
		isRegistered:  true,
		informer:      inf,
		watcher:       watcher,
		cluster:       cluster,
		log:           log,
		converterFunc: settings.converter,
		gvr:           gvr,
	}

	if settings.transformer != nil {
		if err := inf.Informer().SetTransform(settings.transformer); err != nil {
			panic(err)
		}
	}

	if _, err := inf.Informer().AddEventHandler(w); err != nil {
		panic(err)
	}

	return w, gvr
}

func (w *clusterWatcher[T]) Start(ctx context.Context) {
	if !w.isRegistered {
		return
	}
	w.informer.Informer().Run(ctx.Done())
}

func (w *clusterWatcher[T]) convert(obj *unstructured.Unstructured) (T, bool) {
	if w.converterFunc != nil {
		o, ok := w.converterFunc(obj, w.cluster)
		if !ok {
			var def T
			return def, false
		}
		return o.(T), true
	}

	var t T
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &t); err != nil {
		w.log.
			WithError(err).
			WithField("target", fmt.Sprintf("%T", obj)).
			Error("converting object")
		return t, false
	}
	return t, true
}

func (w *clusterWatcher[T]) OnAdd(obj any, isInInitialList bool) {
	t, ok := w.convert(obj.(*unstructured.Unstructured))
	if !ok {
		return
	}
	if w.watcher.onAdd != nil {
		w.watcher.add(w.cluster, t)
	}
}

func (w *clusterWatcher[T]) OnUpdate(oldObj, newObj any) {
	t, ok := w.convert(newObj.(*unstructured.Unstructured))
	if !ok {
		return
	}
	w.watcher.update(w.cluster, t)
}

func (w *clusterWatcher[T]) OnDelete(obj any) {
	a, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = a.Obj
	}

	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		w.log.WithField("type", fmt.Sprintf("%T", obj)).Warn("could not convert object to unstructured")
		return
	}
	t, ok := w.convert(u)
	if !ok {
		return
	}
	w.watcher.remove(w.cluster, t)
}

func (w *clusterWatcher[T]) Client() dynamic.NamespaceableResourceInterface {
	return w.manager.client.Resource(w.gvr)
}

type ImpersonatedClientOption func(s *impersonatedSettings)

type impersonatedSettings struct {
	gvr *schema.GroupVersionResource
}

func WithImpersonatedClientGVR(gvr schema.GroupVersionResource) ImpersonatedClientOption {
	return func(s *impersonatedSettings) {
		s.gvr = &gvr
	}
}

func (w *clusterWatcher[T]) SystemAuthenticatedClient(ctx context.Context, opts ...ImpersonatedClientOption) (dynamic.NamespaceableResourceInterface, error) {
	settings := &impersonatedSettings{}
	for _, opt := range opts {
		opt(settings)
	}

	gvr := w.gvr
	if settings.gvr != nil {
		gvr = *settings.gvr
	}

	return w.manager.client.Resource(gvr), nil
}
