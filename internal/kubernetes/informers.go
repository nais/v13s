package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	schemepkg "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type discoveryResourceLister interface {
	ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error)
}

var newDiscoveryClientForConfig = func(cfg *rest.Config) (discoveryResourceLister, error) {
	return discovery.NewDiscoveryClientForConfig(cfg)
}

func checkServerResources(disc discoveryResourceLister, gvr schema.GroupVersionResource) (*metav1.APIResourceList, error) {
	return disc.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
}

type InformerManager struct {
	clusters map[string]*clusterManager
	ctx      context.Context
	cancel   context.CancelFunc
	queue    *WorkloadEventQueue
	log      logrus.FieldLogger
}

type clusterManager struct {
	discovery discoveryResourceLister
	factory   dynamicinformer.DynamicSharedInformerFactory
	informers map[schema.GroupVersionResource]cache.SharedIndexInformer
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

	clusters := make(map[string]*clusterManager, len(clusterConfig))
	for cluster, cfg := range clusterConfig {
		cfg.UserAgent = "nais.io/v13s"
		dynamicClient, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return nil, err
		}
		if cfg.NegotiatedSerializer == nil {
			cfg.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{CodecFactory: schemepkg.Codecs}
		}
		discoveryConfig := rest.CopyConfig(cfg)
		discoveryConfig.Timeout = 10 * time.Second
		discoveryClient, err := newDiscoveryClientForConfig(discoveryConfig)
		if err != nil {
			return nil, fmt.Errorf("creating discovery client: %w", err)
		}
		clusters[cluster] = &clusterManager{
			discovery: discoveryClient,
			factory:   dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, 4*time.Hour, corev1.NamespaceAll, nil),
			informers: make(map[schema.GroupVersionResource]cache.SharedIndexInformer),
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	return &InformerManager{
		clusters: clusters,
		ctx:      ctx,
		cancel:   cancel,
		queue:    workloadQueue,
		log:      log,
	}, nil
}

func (m *InformerManager) Stop() {
	m.cancel()
}

func (m *InformerManager) Run(onReady func(context.Context, string, func() []*model.Workload)) error {
	defer m.Stop()
	group, ctx := errgroup.WithContext(m.ctx)
	for name, cluster := range m.clusters {
		group.Go(func() error {
			return m.runCluster(ctx, name, cluster, onReady)
		})
	}
	if err := group.Wait(); err != nil {
		return err
	}
	<-m.ctx.Done()
	return nil
}

func (m *InformerManager) runCluster(ctx context.Context, name string, cluster *clusterManager, onReady func(context.Context, string, func() []*model.Workload)) error {
	log := m.log.WithField("cluster", name)
	delay := time.Second
	var resources []schema.GroupVersionResource
	for {
		if ctx.Err() != nil {
			return nil
		}
		var err error
		resources, err = cluster.discover(ctx, log)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			break
		}
		if !retryableDiscoveryError(err) {
			return fmt.Errorf("discovery failed in cluster %s (%s)", name, discoveryErrorDescription(err))
		}
		retryIn := wait.Jitter(delay, 0.2)
		log.WithFields(logrus.Fields{
			"retry_in":   retryIn,
			"error_type": discoveryErrorDescription(err),
		}).Warn("cluster discovery unavailable; retrying")
		timer := time.NewTimer(retryIn)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		delay = min(2*delay, 30*time.Second)
	}

	if len(resources) == 0 {
		log.Warn("no active informers; skipping cluster reconciliation")
		<-ctx.Done()
		return nil
	}

	var syncs []cache.InformerSynced
	for _, gvr := range resources {
		informer := cluster.factory.ForResource(gvr).Informer()
		if _, err := informer.AddEventHandler(newEventHandler(name, m.queue, log)); err != nil {
			return fmt.Errorf("adding event handler for %s in cluster %s: %w", gvr.String(), name, err)
		}
		cluster.informers[gvr] = informer
		syncs = append(syncs, informer.HasSynced)
	}
	cluster.factory.Start(ctx.Done())
	defer cluster.factory.Shutdown()

	log.Info("waiting for cluster caches to sync")
	for {
		syncCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		synced := cache.WaitForCacheSync(syncCtx.Done(), syncs...)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if synced {
			break
		}
		log.Warn("cluster caches not synced; reconciliation deferred")
	}
	log.Info("cluster informers synced; reconciling workloads")
	onReady(ctx, name, func() []*model.Workload {
		return cluster.workloads(name)
	})
	<-ctx.Done()
	return nil
}

func (c *clusterManager) discover(ctx context.Context, log logrus.FieldLogger) ([]schema.GroupVersionResource, error) {
	var resources []schema.GroupVersionResource
	for _, gvr := range gvrs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resList, err := checkServerResources(c.discovery, gvr)
		if apierrors.IsNotFound(err) {
			log.Warnf("group version %s not available", gvr.String())
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, resource := range resList.APIResources {
			if resource.Name == gvr.Resource {
				resources = append(resources, gvr)
				break
			}
		}
	}
	return resources, nil
}

func discoveryErrorDescription(err error) string {
	var causes []string
	for err != nil {
		cause := fmt.Sprintf("%T", err)
		switch err := err.(type) {
		case syscall.Errno:
			cause += ": " + err.Error()
		case apierrors.APIStatus:
			cause += fmt.Sprintf(" (HTTP %d)", err.Status().Code)
		}
		if errors.Is(err, http.ErrSchemeMismatch) {
			return http.ErrSchemeMismatch.Error()
		}
		causes = append(causes, cause)
		err = errors.Unwrap(err)
	}
	return strings.Join(causes, ": ")
}

func retryableDiscoveryError(err error) bool {
	if _, ok := errors.AsType[*oauth2.RetrieveError](err); ok {
		return false
	}
	if apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
		return false
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return true
	}
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return true
	}
	return apierrors.IsServiceUnavailable(err) || apierrors.IsTooManyRequests(err) ||
		apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsInternalError(err) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (c *clusterManager) workloads(name string) []*model.Workload {
	var result []*model.Workload
	for _, informer := range c.informers {
		for _, obj := range informer.GetStore().List() {
			u, ok := obj.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			result = append(result, extractWorkloads(name, u)...)
		}
	}
	return result
}
