package config

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
)

type Config struct {
	ListenAddr                string        `envconfig:"LISTEN_ADDR" default:"0.0.0.0:50051"`
	DatabaseUrl               string        `envconfig:"DATABASE_URL" required:"true"`
	UpdateInterval            time.Duration `envconfig:"UPDATE_INTERVAL" default:"1m"`
	RequiredAudience          string        `envconfig:"REQUIRED_AUDIENCE" default:"vulnz"`
	AuthorizedServiceAccounts []string      `envconfig:"AUTHORIZED_SERVICE_ACCOUNTS" required:"true"`
	LogFormat                 string        `envconfig:"LOG_FORMAT" default:"json"`
	LogLevel                  string        `envconfig:"LOG_LEVEL" default:"info"`
	Tenant                    string        `envconfig:"TENANT" default:"nav"`
	DependencyTrack           DependencyTrackConfig
	K8s                       K8sConfig
}

type DependencyTrackConfig struct {
	Url      string `env:"DEPENDENCYTRACK_URL"`
	Team     string `env:"DEPENDENCYTRACK_TEAM" default:"Administrators"`
	Username string `env:"DEPENDENCYTRACK_USERNAME" default:"v13s"`
	Password string `env:"DEPENDENCYTRACK_PASSWORD"`
}

type K8sConfig struct {
	UseKubeConfig  bool            `env:"V13S_KUBERNETES_USE_KUBECONFIG"`
	Clusters       []string        `env:"V13S_KUBERNETES_CLUSTERS"`
	StaticClusters []StaticCluster `env:"V13S_KUBERNETES_CLUSTERS_STATIC"`
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
	err = envconfig.Process("V13S", cfg)
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

func CreateClusterConfigMap(tenant string, clusters []string, staticClusters []StaticCluster) (ClusterConfigMap, error) {
	configs := ClusterConfigMap{}

	for _, cluster := range clusters {
		configs[cluster] = &rest.Config{
			Host: fmt.Sprintf("https://apiserver.%s.%s.cloud.nais.io", cluster, tenant),
			AuthProvider: &api.AuthProviderConfig{
				Name: GoogleAuthPlugin,
			},
			WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
				return otelhttp.NewTransport(rt, otelhttp.WithServerName(cluster))
			},
		}
	}

	staticConfigs := getStaticClusterConfigs(staticClusters)
	for cluster, cfg := range staticConfigs {
		configs[cluster] = cfg
	}

	return configs, nil
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

func (c *StaticCluster) EnvDecode(value string) error {
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
