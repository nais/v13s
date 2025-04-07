package k8s_new

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	schemepkg "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
	"time"
)

type Manager struct {
	clusters        map[string]*clusterManager
	cacheSyncs      []cache.InformerSynced
	log             logrus.FieldLogger
	resourceCounter metric.Int64UpDownCounter
}

type clusterManager struct {
	client     dynamic.Interface
	informers  map[schema.GroupVersionResource]cache.SharedIndexInformer
	registered bool
}

func NewManager(cfg config.ClusterConfigMap, log logrus.FieldLogger, workloadHandlers ...WorkloadEventHandler) (*Manager, error) {
	clusters := map[string]*clusterManager{}
	mgr := &Manager{
		log: log,
	}
	for cluster, config := range cfg {
		log.Infof("cluster: %s, config: %v", cluster, config)
		dynamicClient, err := dynamic.NewForConfig(config)
		if err != nil {
			return nil, err
		}
		if config.NegotiatedSerializer == nil {
			config.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{CodecFactory: schemepkg.Codecs}
		}
		config.UserAgent = "nais.io/v13s"

		discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
		if err != nil {
			return nil, fmt.Errorf("creating discovery client: %w", err)
		}

		factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, time.Minute, corev1.NamespaceAll, nil)
		infs := map[schema.GroupVersionResource]cache.SharedIndexInformer{}
		for _, handler := range workloadHandlers {
			// Check if the resource is available in the cluster.
			_, err = discoveryClient.ServerResourcesForGroupVersion(handler.GetGVR().GroupVersion().String())
			if err != nil {
				log.WithError(err).Warnf("resource %s not available in cluster %s", handler.GetGVR().String(), cluster)
				continue
			}
			informer := factory.ForResource(handler.GetGVR()).Informer()
			_, err = informer.AddEventHandler(NewWorkloadEventHandler(cluster, gvr, log.WithField("subsystem", "workload-watcher")))
			if err != nil {
				log.WithError(err).Warnf("failed to add event handler for resource %s in cluster %s", gvr.String(), cluster)
				continue
			}
			infs[gvr] = informer
			mgr.addCacheSync(informer.HasSynced)
		}

		clusters[cluster] = &clusterManager{
			client:    dynamicClient,
			informers: infs,
		}

	}

	return &Manager{
		clusters: clusters,
		log:      log,
	}, nil
}

type WorkloadHandler struct {
	cluster string
	gvr     schema.GroupVersionResource
	log     logrus.FieldLogger
}

func NewWorkloadHandler(cluster string, gvr schema.GroupVersionResource, log logrus.FieldLogger) *WorkloadHandler {
	return &WorkloadHandler{
		cluster: cluster,
		gvr:     gvr,
		log:     log,
	}
}

func (w WorkloadHandler) OnAdd(obj any, isInInitialList bool) {
	_, _ = w.asWorkload(obj.(*unstructured.Unstructured))
}

func (w WorkloadHandler) OnUpdate(oldObj, newObj any) {
	_, _ = w.asWorkload(newObj.(*unstructured.Unstructured))
}

func (w WorkloadHandler) OnDelete(obj any) {
	_, _ = w.asWorkload(obj.(*unstructured.Unstructured))
}

var _ cache.ResourceEventHandler = &WorkloadHandler{}

func (w *WorkloadHandler) asWorkload(obj *unstructured.Unstructured) (*model.Workload, bool) {

	obj.GroupVersionKind()
	switch obj.GetKind() {
	case "Deployment":

	}
	return &model.Workload{}, true
}

func convert[T any](obj *unstructured.Unstructured, t *T, log logrus.FieldLogger) (*T, bool) {
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &t); err != nil {
		log.
			WithError(err).
			WithField("target", fmt.Sprintf("%T", obj)).
			Error("converting object")
		return t, false
	}
	return t, true
}

func (m *Manager) addCacheSync(sync cache.InformerSynced) {
	m.cacheSyncs = append(m.cacheSyncs, sync)
}

func (m *Manager) WaitForReady(ctx context.Context) bool {
	return cache.WaitForCacheSync(ctx.Done(), m.cacheSyncs...)
}

func (m *Manager) Start(ctx context.Context) {
	for _, cluster := range m.clusters {
		if cluster.registered {
			continue
		}
		for _, informer := range cluster.informers {
			go informer.Run(ctx.Done())
		}
		cluster.registered = true
	}
}
