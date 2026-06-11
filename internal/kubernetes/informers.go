package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	schemepkg "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
)

type InformerManager struct {
	clusters   map[string]*clusterManager
	cacheSyncs []cache.InformerSynced
	log        logrus.FieldLogger
	// TODO: not in use
	// resourceCounter metric.Int64UpDownCounter
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

func NewInformerManager(ctx context.Context, tenant string, k8sCfg config.K8sConfig, workloadQueue *WorkloadEventQueue, log logrus.FieldLogger) (*InformerManager, error) {
	clusterConfig, err := config.CreateClusterConfigMap(tenant, k8sCfg)
	if err != nil {
		return nil, fmt.Errorf("creating cluster config map: %w", err)
	}

	clusters := map[string]*clusterManager{}
	mgr := &InformerManager{
		log: log,
	}
	for cluster, cfg := range clusterConfig {
		dynamicClient, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return nil, err
		}
		if cfg.NegotiatedSerializer == nil {
			cfg.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{CodecFactory: schemepkg.Codecs}
		}
		cfg.UserAgent = "nais.io/v13s"

		discoveryClient, err := discovery.NewDiscoveryClientForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating discovery client: %w", err)
		}

		factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, 4*time.Hour, corev1.NamespaceAll, nil)
		infs := map[schema.GroupVersionResource]cache.SharedIndexInformer{}
		for _, gvr := range gvrs {
			// Check if the resource is available in the cluster.
			resList, err := discoveryClient.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
			if err != nil {
				if _, ok := errors.AsType[*oauth2.RetrieveError](err); ok {
					mgr.Stop()
					return nil, fmt.Errorf("authentication error for cluster %s: %w", cluster, err)
				}
				log.WithError(err).Warnf("group version %s not available in cluster %s", gvr.String(), cluster)
			}

			found := false
			for _, apiRes := range resList.APIResources {
				if apiRes.Name == gvr.Resource {
					found = true
					break
				}
			}

			if !found {
				log.Warnf("resource %s not available in cluster %s", gvr.String(), cluster)
				continue
			}

			informer := factory.ForResource(gvr).Informer()
			log.WithFields(logrus.Fields{
				"cluster":  cluster,
				"resource": gvr.String(),
			}).Info("creating informer")

			_, err = informer.AddEventHandler(newEventHandler(cluster, workloadQueue, log.WithField("cluster", cluster)))
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
	mgr.clusters = clusters
	mgr.start(ctx)

	return mgr, nil
}

func (m *InformerManager) Stop() {
	for _, cluster := range m.clusters {
		cluster.factory.Shutdown()
	}
}

func (m *InformerManager) WaitForReady(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		m.log.WithError(ctx.Err()).Error("WaitForReady: context already cancelled before WaitForCacheSync")
		return false
	default:
	}
	m.log.Infof("WaitForReady: waiting for %d cache syncs", len(m.cacheSyncs))
	result := cache.WaitForCacheSync(ctx.Done(), m.cacheSyncs...)
	if !result {
		select {
		case <-ctx.Done():
			m.log.WithError(ctx.Err()).Error("WaitForReady: context cancelled during WaitForCacheSync")
		default:
			m.log.Error("WaitForReady: timed out before all caches synced")
		}
	}
	return result
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

// ListWorkloadsByCluster returns all workloads currently in the informer cache,
// keyed by cluster name. Every managed cluster is present in the map — clusters
// with no live workloads have an empty slice, which lets ReconcileWorkloads
// delete DB entries for those clusters too.
// Clusters with no active informers are excluded to avoid false positives.
func (m *InformerManager) ListWorkloadsByCluster() map[string][]*model.Workload {
	result := make(map[string][]*model.Workload, len(m.clusters))
	for cluster, clusterMgr := range m.clusters {
		if len(clusterMgr.informers) == 0 {
			m.log.Warnf("reconcile: skipping cluster %s — no active informers, cannot safely determine live workloads", cluster)
			continue
		}
		result[cluster] = make([]*model.Workload, 0)
		for _, informer := range clusterMgr.informers {
			for _, obj := range informer.GetStore().List() {
				u, ok := obj.(*unstructured.Unstructured)
				if !ok {
					continue
				}
				result[cluster] = append(result[cluster], extractWorkloads(cluster, u)...)
			}
		}
	}
	return result
}
