package kubernetes

import (
	"context"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

type WatchOption func(*watcherSettings)

func WithConverter(fn func(o *unstructured.Unstructured, environmentName string) (obj any, ok bool)) WatchOption {
	return func(m *watcherSettings) {
		m.converter = fn
	}
}

func WithTransformer(fn cache.TransformFunc) WatchOption {
	return func(m *watcherSettings) {
		m.transformer = fn
	}
}

func WithGVR(gvr schema.GroupVersionResource) WatchOption {
	return func(m *watcherSettings) {
		m.gvr = &gvr
	}
}

func WithInformerFilter(labelSelector string) WatchOption {
	return func(m *watcherSettings) {
		m.filterLabelSelector = labelSelector
	}
}

type watcherSettings struct {
	converter           func(o *unstructured.Unstructured, environmentName string) (obj any, ok bool)
	transformer         cache.TransformFunc
	gvr                 *schema.GroupVersionResource
	filterLabelSelector string
}

type WatcherHook[T Object] func(cluster string, obj T)

type Watcher[T Object] struct {
	watchers        []*clusterWatcher[T]
	log             logrus.FieldLogger
	resourceCounter metric.Int64UpDownCounter
	watchedType     string
	onAdd           WatcherHook[T]
	onUpdate        WatcherHook[T]
	onRemove        WatcherHook[T]
}

func newWatcher[T Object](mgr *Manager, obj T, settings *watcherSettings, log logrus.FieldLogger) *Watcher[T] {
	w := &Watcher[T]{
		log:             log,
		resourceCounter: mgr.resourceCounter,
	}
	for cluster, client := range mgr.managers {
		if mgr.replaceEnvironmentNames != nil && mgr.replaceEnvironmentNames[cluster] != "" {
			cluster = mgr.replaceEnvironmentNames[cluster]
		}
		watcher, gvr := newClusterWatcher(client, cluster, w, obj, settings, log.WithField("cluster", cluster))
		if !watcher.isRegistered {
			continue
		}
		w.watchedType = gvr.String()

		w.watchers = append(w.watchers, watcher)
		mgr.addCacheSync(watcher.informer.Informer().HasSynced)
	}
	return w
}

func (w *Watcher[T]) Start(ctx context.Context) {
	for _, watcher := range w.watchers {
		go watcher.Start(ctx)
	}
}

func (w *Watcher[T]) Enabled() bool {
	for _, watcher := range w.watchers {
		if watcher.isRegistered {
			return true
		}
	}

	return false
}

func (w *Watcher[T]) add(cluster string, obj T) {
	if w.onAdd != nil {
		w.onAdd(cluster, obj)
	}

	//	w.resourceCounter.Add(context.TODO(), 1, metric.WithAttributes(attribute.String("type", w.watchedType), attribute.String("action", "add")))
	w.log.WithFields(logrus.Fields{
		"cluster":   cluster,
		"name":      obj.GetName(),
		"namespace": obj.GetNamespace(),
	}).Debug("Adding object")
}

func (w *Watcher[T]) remove(cluster string, obj T) {
	if w.onRemove != nil {
		w.onRemove(cluster, obj)
	}

	//	w.resourceCounter.Add(context.TODO(), 1, metric.WithAttributes(attribute.String("type", w.watchedType), attribute.String("action", "remove")))
	w.log.WithFields(logrus.Fields{
		"cluster":   cluster,
		"name":      obj.GetName(),
		"namespace": obj.GetNamespace(),
		"gvr":       w.watchedType,
	}).Debug("Removing object")
}

func (w *Watcher[T]) update(cluster string, obj T) {
	if w.onUpdate != nil {
		w.onUpdate(cluster, obj)
	}
	//w.resourceCounter.Add(context.TODO(), 1, metric.WithAttributes(attribute.String("type", w.watchedType), attribute.String("action", "update")))
	w.log.WithFields(logrus.Fields{
		"cluster":   cluster,
		"name":      obj.GetName(),
		"namespace": obj.GetNamespace(),
		"gvr":       w.watchedType,
	}).Debug("Updating object")
}

func (w *Watcher[T]) OnRemove(fn WatcherHook[T]) {
	w.onRemove = fn
}

func (w *Watcher[T]) OnUpdate(fn WatcherHook[T]) {
	w.onUpdate = fn
}

func (w *Watcher[T]) OnAdd(fn WatcherHook[T]) {
	w.onAdd = fn
}
