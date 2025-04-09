package k8s

import (
	"context"
	"fmt"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	schemepkg "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
)

type InformerManager struct {
	clusters        map[string]*clusterManager
	cacheSyncs      []cache.InformerSynced
	log             logrus.FieldLogger
	resourceCounter metric.Int64UpDownCounter
}

type clusterManager struct {
	client     dynamic.Interface
	factory    dynamicinformer.DynamicSharedInformerFactory
	informers  map[schema.GroupVersionResource]cache.SharedIndexInformer
	registered bool
}

var gvrs = []schema.GroupVersionResource{
	{
		Group:    "apps",
		Version:  "v1",
		Resource: "deployments",
	},
	{
		Group:    "nais.io",
		Version:  "v1",
		Resource: "naisjobs",
	},
}

func NewInformerManager(ctx context.Context, tenant string, cfg config.K8sConfig, log logrus.FieldLogger) (*InformerManager, error) {
	clusterConfig, err := config.CreateClusterConfigMap(tenant, cfg.Clusters, cfg.StaticClusters)
	if err != nil {
		return nil, fmt.Errorf("creating cluster config map: %w", err)
	}

	clusters := map[string]*clusterManager{}
	mgr := &InformerManager{
		log: log,
	}
	for cluster, config := range clusterConfig {
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

		factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, 4*time.Hour, corev1.NamespaceAll, nil)
		infs := map[schema.GroupVersionResource]cache.SharedIndexInformer{}
		for _, gvr := range gvrs {
			// Check if the resource is available in the cluster.
			_, err = discoveryClient.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
			if err != nil {
				log.WithError(err).Warnf("resource %s not available in cluster %s", gvr.String(), cluster)
				continue
			}
			informer := factory.ForResource(gvr).Informer()
			log.WithFields(logrus.Fields{
				"cluster":  cluster,
				"resource": gvr.String(),
			}).Info("creating informer")

			_, err = informer.AddEventHandler(newWorkloadHandler(cluster, log.WithField("cluster", cluster)))
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
			factory:   factory,
		}

	}
	m := &InformerManager{
		clusters: clusters,
		log:      log,
	}
	m.start(ctx)

	return m, nil
}

func (m *InformerManager) Stop() {
	for _, cluster := range m.clusters {
		cluster.factory.Shutdown()
	}
}

func (m *InformerManager) WaitForReady(ctx context.Context) bool {
	return cache.WaitForCacheSync(ctx.Done(), m.cacheSyncs...)
}

func (m *InformerManager) start(ctx context.Context) {
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

func (m *InformerManager) addCacheSync(sync cache.InformerSynced) {
	m.cacheSyncs = append(m.cacheSyncs, sync)
}
