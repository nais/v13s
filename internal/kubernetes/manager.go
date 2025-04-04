package kubernetes

import (
	"context"
	"fmt"
	nais "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/v13s/internal/config"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"os"

	"github.com/sirupsen/logrus"
	//"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	schemepkg "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type Discovery interface {
	ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error)
}

type settings struct {
	clientCreator           func(cluster string) (dynamic.Interface, Discovery, *rest.Config, error)
	replaceEnvironmentNames map[string]string
}

type Option func(*settings)

func WithClientCreator(fn func(cluster string) (dynamic.Interface, Discovery, *rest.Config, error)) Option {
	return func(m *settings) {
		m.clientCreator = fn
	}
}

func WithReplaceEnvironmentNames(m map[string]string) Option {
	return func(s *settings) {
		s.replaceEnvironmentNames = m
	}
}

type Manager struct {
	managers                map[string]*clusterManager
	scheme                  *runtime.Scheme
	log                     logrus.FieldLogger
	replaceEnvironmentNames map[string]string

	cacheSyncs      []cache.InformerSynced
	resourceCounter metric.Int64UpDownCounter
}

func NewManager(clusterConfig config.ClusterConfigMap, log logrus.FieldLogger, opts ...Option) (*Manager, error) {
	scheme := runtime.NewScheme()
	funcs := []func(s *runtime.Scheme) error{
		nais.AddToScheme,
		corev1.AddToScheme,
		v1.AddToScheme,
	}
	for _, f := range funcs {
		if err := f(scheme); err != nil {
			return nil, err
		}
	}

	/*meter := otel.GetMeterProvider().Meter("nais_api_watcher")
	udCounter, err := meter.Int64UpDownCounter("nais_api_watcher_resources", metric.WithDescription("Number of resources watched by the watcher"))
	if err != nil {
		return nil, fmt.Errorf("creating resources counter: %w", err)
	}
	*/

	s := &settings{
		clientCreator: func(cluster string) (dynamic.Interface, Discovery, *rest.Config, error) {
			config, ok := clusterConfig[cluster]
			if !ok {
				return nil, nil, nil, fmt.Errorf("no config for cluster %s", cluster)
			}

			if cluster == "management" && config == nil {
				var err error
				config, err = rest.InClusterConfig()
				if err != nil {
					return nil, nil, nil, fmt.Errorf("creating in-cluster config: %w", err)
				}
			}

			if config.NegotiatedSerializer == nil {
				config.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{CodecFactory: schemepkg.Codecs}
			}

			config.UserAgent = "nais.io/v13s"
			client, err := dynamic.NewForConfig(config)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("creating REST client: %w", err)
			}
			dynamicClient, err := discovery.NewDiscoveryClientForConfig(config)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("creating discovery client: %w", err)
			}
			return client, dynamicClient, config, nil
		},
	}
	for _, opt := range opts {
		opt(s)
	}

	managers := map[string]*clusterManager{}

	for cluster := range clusterConfig {
		client, discovery, cfg, err := s.clientCreator(cluster)
		if err != nil {
			return nil, fmt.Errorf("creating client for cluster %s: %w", cluster, err)
		}
		mgr, err := newClusterManager(scheme, client, discovery, cfg, log.WithField("cluster", cluster))
		if err != nil {
			return nil, fmt.Errorf("creating cluster manager: %w", err)
		}

		managers[cluster] = mgr
	}

	return &Manager{
		scheme:   scheme,
		managers: managers,
		log:      log,
		//resourceCounter:         udCounter,
		replaceEnvironmentNames: s.replaceEnvironmentNames,
	}, nil
}

func NewWatcherManagers(cfg config.Config, log logrus.Entry) ([]*Manager, error) {
	watchers := make([]*Manager, 0)
	clusterConfig, err := config.CreateClusterConfigMap(cfg.Tenant, cfg.K8s.Clusters, cfg.K8s.StaticClusters)
	if err != nil {
		return nil, fmt.Errorf("creating cluster config map: %w", err)
	}

	if os.Getenv("KUBECONFIG") != "" {
		// TODO: how to use kubeconfig in the watcher manager?
		envConfig := os.Getenv("KUBECONFIG")
		kubeConfig, err := clientcmd.BuildConfigFromFlags("", envConfig)
		if err != nil {
			return nil, fmt.Errorf("building kubeconfig from flags: %w", err)
		}
		log.Infof("starting with kubeconfig: %s", envConfig)
		watcherMgr, err := NewManager(config.ClusterConfigMap{"kubeconfig": kubeConfig}, log.WithField("subsystem", "k8s_watcher"))
		if err != nil {
			return nil, fmt.Errorf("create k8s watcher manager: %w", err)
		}
		watchers = append(watchers, watcherMgr)
	} else {
		watcherMgr, err := NewManager(clusterConfig, log.WithField("subsystem", "k8s_watcher"))
		if err != nil {
			return nil, fmt.Errorf("create k8s watcher manager: %w", err)
		}
		mgmtWatcher, err := NewManager(config.ClusterConfigMap{"management": nil}, log.WithField("subsystem", "k8s_watcher"))
		if err != nil {
			return nil, fmt.Errorf("create k8s watcher manager for management: %w", err)
		}
		watchers = append(watchers, watcherMgr, mgmtWatcher)
	}

	return watchers, nil
}

func (m *Manager) Stop() {
	for _, mgr := range m.managers {
		if mgr.createdInformer != nil {
			mgr.createdInformer.Shutdown()
		}
		for _, inf := range mgr.createdFilteredInformers {
			inf.Shutdown()
		}
	}
}

func (m *Manager) WaitForReady(ctx context.Context) bool {
	return cache.WaitForCacheSync(ctx.Done(), m.cacheSyncs...)
}

func (m *Manager) GetDynamicClients() map[string]dynamic.Interface {
	clients := map[string]dynamic.Interface{}
	for cluster, mgr := range m.managers {
		clients[cluster] = mgr.client
	}

	return clients
}

func (m *Manager) addCacheSync(sync cache.InformerSynced) {
	m.cacheSyncs = append(m.cacheSyncs, sync)
}

func Watch[T Object](mgr *Manager, obj T, opts ...WatchOption) *Watcher[T] {
	settings := &watcherSettings{}
	for _, opt := range opts {
		opt(settings)
	}
	return newWatcher(mgr, obj, settings, mgr.log)
}
