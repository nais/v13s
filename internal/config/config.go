package config

import (
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/nais/v13s/internal/sources"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
)

type Config struct {
	ListenAddr                string        `envconfig:"LISTEN_ADDR" default:"0.0.0.0:50051"`
	InternalListenAddr        string        `envconfig:"INTERNAL_LISTEN_ADDR" default:"127.0.0.1:8000"`
	DatabaseUrl               string        `envconfig:"DATABASE_URL" required:"true"`
	UpdateInterval            time.Duration `envconfig:"UPDATE_INTERVAL" default:"1m"`
	RequiredAudience          string        `envconfig:"REQUIRED_AUDIENCE" default:"vulnz"`
	AuthorizedServiceAccounts []string      `envconfig:"AUTHORIZED_SERVICE_ACCOUNTS" required:"true"`
	LogFormat                 string        `envconfig:"LOG_FORMAT" default:"json"`
	LogLevel                  string        `envconfig:"LOG_LEVEL" default:"info"`
	Tenant                    string        `envconfig:"TENANT" default:"nav"`
	DependencyTrack           sources.DependencyTrackConfig
	Kev                       KevConfig
	Osv                       OsvConfig
	K8s                       K8sConfig
	LeaderElection            LeaderElectionConfig
	GithubOrganizations       []string `envconfig:"GITHUB_ORGANIZATIONS"`
	Metrics                   MetricConfig
	ReconcileDeletionEnabled  bool `envconfig:"RECONCILE_DELETION_ENABLED" default:"false"`
	Updater                   UpdaterConfig
}

type UpdaterConfig struct {
	RuntimeOrchestrationEnabled bool   `envconfig:"UPDATER_RUNTIME_ORCHESTRATION_ENABLED" default:"true"`
	ResyncEnabled               bool   `envconfig:"UPDATER_RESYNC_ENABLED" default:"true"`
	MarkUnusedEnabled           bool   `envconfig:"UPDATER_MARK_UNUSED_ENABLED" default:"true"`
	MarkUnusedCron              string `envconfig:"UPDATER_MARK_UNUSED_CRON" default:"*/30 * * * *"`
	MarkUntrackedEnabled        bool   `envconfig:"UPDATER_MARK_UNTRACKED_ENABLED" default:"true"`
	MarkUntrackedCron           string `envconfig:"UPDATER_MARK_UNTRACKED_CRON" default:"*/20 * * * *"`
	RefreshSummaryEnabled       bool   `envconfig:"UPDATER_REFRESH_SUMMARY_ENABLED" default:"true"`
	RefreshSummaryCron          string `envconfig:"UPDATER_REFRESH_SUMMARY_CRON" default:"30 4 * * *"`
	RefreshLifetimesEnabled     bool   `envconfig:"UPDATER_REFRESH_LIFETIMES_ENABLED" default:"true"`
	RefreshLifetimesCron        string `envconfig:"UPDATER_REFRESH_LIFETIMES_CRON" default:"0 5 * * *"`
	SyncKevEnabled              bool   `envconfig:"UPDATER_SYNC_KEV_ENABLED" default:"true"`
	SyncKevCron                 string `envconfig:"UPDATER_SYNC_KEV_CRON" default:"0 6 * * *"`
	SyncOsvEnabled              bool   `envconfig:"UPDATER_SYNC_OSV_ENABLED" default:"true"`
	SyncOsvCron                 string `envconfig:"UPDATER_SYNC_OSV_CRON" default:"0 7 * * *"`
	RekeySuppressedEnabled      bool   `envconfig:"UPDATER_REKEY_SUPPRESSED_ENABLED" default:"true"`
	RekeySuppressedCron         string `envconfig:"UPDATER_REKEY_SUPPRESSED_CRON" default:"0 8 * * *"`
}

type DependencyTrackConfig struct {
	Url      string `envconfig:"DEPENDENCYTRACK_URL"`
	Username string `envconfig:"DEPENDENCYTRACK_USERNAME" default:"v13s"`
	Password string `envconfig:"DEPENDENCYTRACK_PASSWORD"`
}

type KevConfig struct {
	CatalogURL string `envconfig:"KEV_CATALOG_URL"`
}

type OsvConfig struct {
	BaseURL string `envconfig:"OSV_BASE_URL"`
}

type K8sConfig struct {
	SelfCluster    string          `envconfig:"KUBERNETES_SELF_CLUSTER" default:"management"`
	Clusters       []string        `envconfig:"KUBERNETES_CLUSTERS"`
	StaticClusters []StaticCluster `envconfig:"KUBERNETES_CLUSTERS_STATIC"`
}

type LeaderElectionConfig struct {
	FakeEnabled     bool   `envconfig:"LEADER_ELECTION_FAKE_ENABLED" default:"false"`
	LocalKubernetes bool   `envconfig:"LEADER_ELECTION_LOCAL_KUBERNETES" default:"false"`
	LeaseName       string `envconfig:"LEADER_ELECTION_LEASE_NAME" default:"v13s-lease"`
	LeaseNamespace  string `envconfig:"LEADER_ELECTION_LEASE_NAMESPACE" default:"nais-system"`
}

type MetricConfig struct {
	OtelExporterOtlpEndpoint             string        `envconfig:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	PrometheusMetricsPushgatewayEndpoint string        `envconfig:"PROMETHEUS_METRICS_PUSHGATEWAY_ENDPOINT"`
	PrometheusPushgatewayDuration        time.Duration `envconfig:"PROMETHEUS_PUSHGATEWAY_DURATION" default:"2m"`
	WorkloadMetricsRefreshDuration       time.Duration `envconfig:"WORKLOAD_METRICS_REFRESH_DURATION" default:"5m"`
}

func (k *K8sConfig) AllClusterNames() []string {
	clusters := append([]string{}, k.Clusters...)
	for _, c := range k.StaticClusters {
		clusters = append(clusters, c.Name)
	}
	return clusters
}

func NewConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	cfg := &Config{}
	err = envconfig.Process("", cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

type StaticCluster struct {
	Name  string
	Host  string
	Token string
}

type ClusterConfigMap map[string]*rest.Config

func CreateClusterConfigMap(tenant string, config K8sConfig) (ClusterConfigMap, error) {
	configs := ClusterConfigMap{}

	for _, cluster := range config.Clusters {
		configs[cluster] = CreateRemoteClusterConfig(cluster, tenant)
	}
	if config.SelfCluster != "" {
		mgmtCfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("creating in-cluster config: %w", err)
		}
		configs[config.SelfCluster] = mgmtCfg
	}

	staticConfigs := getStaticClusterConfigs(config.StaticClusters)
	maps.Copy(configs, staticConfigs)

	return configs, nil
}

func CreateRemoteClusterConfig(cluster, tenant string) *rest.Config {
	host := fmt.Sprintf("https://apiserver.%s.cloud.nais.io", tenant)
	if cluster != "" {
		host = fmt.Sprintf("https://apiserver.%s.%s.cloud.nais.io", cluster, tenant)
	}
	return &rest.Config{
		Host: host,
		AuthProvider: &api.AuthProviderConfig{
			Name: GoogleAuthPlugin,
		},
		WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
			return otelhttp.NewTransport(rt, otelhttp.WithServerName(cluster))
		},
	}
}

func getStaticClusterConfigs(clusters []StaticCluster) ClusterConfigMap {
	configs := ClusterConfigMap{}
	for _, cluster := range clusters {
		configs[cluster.Name] = &rest.Config{
			Host:        cluster.Host,
			BearerToken: cluster.Token,
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: true,
			},
			WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
				return otelhttp.NewTransport(rt, otelhttp.WithServerName(cluster.Name))
			},
		}
	}
	return configs
}

func (c *StaticCluster) Decode(value string) error {
	if value == "" {
		return nil
	}

	parts := strings.Split(value, "|")
	if len(parts) != 3 {
		return fmt.Errorf(`invalid static cluster entry: %q. Must be on format "name|host|token"`, value)
	}

	name := strings.TrimSpace(parts[0])
	if name == "" {
		return fmt.Errorf("invalid static cluster entry: %q. Name must not be empty", value)
	}

	host := strings.TrimSpace(parts[1])
	if host == "" {
		return fmt.Errorf("invalid static cluster entry: %q. Host must not be empty", value)
	}

	token := strings.TrimSpace(parts[2])
	if token == "" {
		return fmt.Errorf("invalid static cluster entry: %q. Token must not be empty", value)
	}

	*c = StaticCluster{
		Name:  name,
		Host:  host,
		Token: token,
	}
	return nil
}
