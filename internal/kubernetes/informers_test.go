package kubernetes

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// fakeResourceLister stands in for discovery.DiscoveryInterface in tests.
type fakeResourceLister struct {
	err     error
	resList *metav1.APIResourceList
	list    func(string) (*metav1.APIResourceList, error)
}

func (f *fakeResourceLister) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	if f.list != nil {
		return f.list(groupVersion)
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.resList, nil
}

var testGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

func TestCheckServerResources_Success(t *testing.T) {
	want := &metav1.APIResourceList{
		GroupVersion: "apps/v1",
		APIResources: []metav1.APIResource{{Name: "deployments"}},
	}
	lister := &fakeResourceLister{resList: want}

	got, err := checkServerResources(lister, testGVR)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != want {
		t.Fatalf("expected %+v, got %+v", want, got)
	}
}

// Reproduces the original panic: a network error must surface as a non-nil
// error, never as a nil list with a nil error.
func TestCheckServerResources_NetworkErrorIsNotSilentlyNil(t *testing.T) {
	netErr := fmt.Errorf("dial tcp: lookup apiserver.dev.example.cloud.nais.io: no such host")
	lister := &fakeResourceLister{err: netErr}

	resList, err := checkServerResources(lister, testGVR)

	if err == nil {
		t.Fatal("expected a non-nil error for a network failure")
	}
	if resList != nil {
		t.Fatalf("expected nil resource list on error, got %+v", resList)
	}
	if !errors.Is(err, netErr) {
		t.Fatalf("expected the network error to be returned, got %v", err)
	}
	if apierrors.IsNotFound(err) {
		t.Fatal("a network error must not be classified as not-found")
	}
}

func TestCheckServerResources_NotFoundIsClassifiedAsNotFound(t *testing.T) {
	notFound := apierrors.NewNotFound(schema.GroupResource{Group: "nais.io", Resource: "naisjobs"}, "")
	lister := &fakeResourceLister{err: notFound}

	resList, err := checkServerResources(lister, testGVR)

	if err == nil {
		t.Fatal("expected an error for a not-found response")
	}
	if resList != nil {
		t.Fatalf("expected nil resource list, got %+v", resList)
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected IsNotFound(err) to be true, got %v", err)
	}
}

func TestCheckServerResources_AuthErrorIsClassifiedAsRetrieveError(t *testing.T) {
	authErr := &oauth2.RetrieveError{ErrorCode: "invalid_grant"}
	lister := &fakeResourceLister{err: authErr}

	resList, err := checkServerResources(lister, testGVR)

	if err == nil {
		t.Fatal("expected an error for an auth failure")
	}
	if resList != nil {
		t.Fatalf("expected nil resource list, got %+v", resList)
	}
	if _, ok := errors.AsType[*oauth2.RetrieveError](err); !ok {
		t.Fatalf("expected *oauth2.RetrieveError, got %v", err)
	}
}

func TestNewInformerManager_NotFoundDiscoveryResponseSkipsInformer(t *testing.T) {
	discovered := make(chan string, 2)
	manager, _ := newTestInformerManager(t, map[string]discoveryResourceLister{
		"dev": &fakeResourceLister{list: func(gv string) (*metav1.APIResourceList, error) {
			discovered <- gv
			return nil, apierrors.NewNotFound(schema.GroupResource{Group: "apps", Resource: "v1"}, "")
		}},
	})
	ready := make(chan string, 1)
	wait := runTestInformerManager(t, manager, func(_ context.Context, cluster string, _ func() []*model.Workload) {
		ready <- cluster
	})
	receiveCluster(t, discovered)
	receiveCluster(t, discovered)
	manager.Stop()
	require.NoError(t, wait())
	require.Empty(t, ready)
	require.Empty(t, manager.clusters["dev"].informers)
}

func TestNewInformerManager_UnknownDiscoveryErrorFails(t *testing.T) {
	restoreDiscoveryClient := replaceDiscoveryClient(t, &fakeResourceLister{
		err: fmt.Errorf("discovery unavailable"),
	})
	defer restoreDiscoveryClient()

	manager, err := NewInformerManager(
		t.Context(),
		"tenant",
		config.K8sConfig{
			SelfCluster: "",
			StaticClusters: []config.StaticCluster{{
				Name: "test-cluster",
				Host: "https://unused.example",
			}},
		},
		nil,
		logrus.New(),
	)
	require.NoError(t, err)
	wait := runTestInformerManager(t, manager, func(context.Context, string, func() []*model.Workload) {
		t.Error("cluster with failed discovery must not be reconciled")
	})
	err = wait()
	require.Error(t, err)
	if !strings.Contains(err.Error(), "discovery failed") {
		t.Fatalf("expected a discovery failure, got %v", err)
	}
}

func TestNewInformerManager_UnavailableClustersDoNotPreventStartup(t *testing.T) {
	restoreDiscoveryClient := replaceDiscoveryClient(t, &fakeResourceLister{
		err: &net.DNSError{Name: "apiserver.prod.example", IsNotFound: true},
	})
	defer restoreDiscoveryClient()

	manager, err := NewInformerManager(
		t.Context(),
		"tenant",
		config.K8sConfig{
			StaticClusters: []config.StaticCluster{{
				Name: "prod",
				Host: "https://unused.example",
			}},
		},
		nil,
		logrus.New(),
	)
	if err != nil {
		t.Fatalf("unavailable clusters must not prevent startup: %v", err)
	}
	t.Cleanup(manager.Stop)
}

func TestInformerManager_ClustersConnectIndependentlyAndRecover(t *testing.T) {
	var recovered atomic.Bool
	manager, clients := newTestInformerManager(t, map[string]discoveryResourceLister{
		"dev": &fakeResourceLister{list: availableResources},
		"prod": &fakeResourceLister{list: func(gv string) (*metav1.APIResourceList, error) {
			if gv == "nais.io/v1" && !recovered.Load() {
				return nil, &net.DNSError{Name: "apiserver.prod.example", IsNotFound: true}
			}
			return availableResources(gv)
		}},
	})
	ready := make(chan string, 10)
	wait := runTestInformerManager(t, manager, func(_ context.Context, cluster string, snapshot func() []*model.Workload) {
		workloads := snapshot()
		if len(workloads) != 1 || workloads[0].Cluster != cluster {
			t.Errorf("expected the synced workload for %s, got %+v", cluster, workloads)
		}
		ready <- cluster
	})
	require.Equal(t, "dev", receiveCluster(t, ready))
	require.Empty(t, ready)

	recovered.Store(true)
	require.Equal(t, "prod", receiveCluster(t, ready))
	_, err := clients["prod"].Resource(testGVR).Namespace("team").Update(
		t.Context(), testDeployment("updated"), metav1.UpdateOptions{},
	)
	require.NoError(t, err)
	timeout := time.After(3 * time.Second)
	for {
		select {
		case workload := <-manager.queue.Updated:
			if workload.Cluster == "prod" && workload.ImageTag == "updated" {
				manager.Stop()
				require.NoError(t, wait())
				require.Empty(t, ready, "a cluster must only reconcile once")
				return
			}
		case <-timeout:
			t.Fatal("expected informer update after the cluster recovered")
		}
	}
}

func TestInformerManager_AllClustersUnavailable(t *testing.T) {
	attempted := make(chan string, 10)
	listers := make(map[string]discoveryResourceLister)
	for _, cluster := range []string{"dev", "prod"} {
		listers[cluster] = &fakeResourceLister{list: func(string) (*metav1.APIResourceList, error) {
			attempted <- cluster
			return nil, apierrors.NewServiceUnavailable("not provisioned")
		}}
	}
	manager, _ := newTestInformerManager(t, listers)
	ready := make(chan string, 2)
	wait := runTestInformerManager(t, manager, func(_ context.Context, cluster string, _ func() []*model.Workload) {
		ready <- cluster
	})
	require.ElementsMatch(t, []string{"dev", "prod"}, []string{
		receiveCluster(t, attempted), receiveCluster(t, attempted),
	})
	manager.Stop()
	require.NoError(t, wait())
	require.Empty(t, ready)
}

func TestInformerManager_PartialCacheSyncDoesNotReconcile(t *testing.T) {
	manager, clients := newTestInformerManager(t, map[string]discoveryResourceLister{
		"dev": &fakeResourceLister{list: availableResources},
	})
	listed := make(chan string, 1)
	clients["dev"].PrependReactor("list", "naisjobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		select {
		case listed <- "dev":
		default:
		}
		return true, nil, apierrors.NewServiceUnavailable("list unavailable")
	})
	ready := make(chan string, 1)
	wait := runTestInformerManager(t, manager, func(_ context.Context, cluster string, _ func() []*model.Workload) {
		ready <- cluster
	})
	receiveCluster(t, listed)
	manager.Stop()
	require.NoError(t, wait())
	require.Empty(t, ready)
}

func TestInformerManager_PermanentDiscoveryErrorsFail(t *testing.T) {
	const secret = "sensitive-response"
	for name, discoveryErr := range map[string]error{
		"oauth":   &oauth2.RetrieveError{Body: []byte(secret)},
		"401":     apierrors.NewUnauthorized(secret),
		"403":     apierrors.NewForbidden(schema.GroupResource{Resource: "deployments"}, "", errors.New(secret)),
		"tls":     x509.UnknownAuthorityError{},
		"unknown": errors.New(secret),
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			manager, _ := newTestInformerManager(t, map[string]discoveryResourceLister{
				"dev": &fakeResourceLister{list: func(string) (*metav1.APIResourceList, error) {
					calls.Add(1)
					return nil, discoveryErr
				}},
			})
			wait := runTestInformerManager(t, manager, func(context.Context, string, func() []*model.Workload) {
				t.Error("failed discovery must not reconcile")
			})
			err := wait()
			require.Error(t, err)
			require.NotContains(t, err.Error(), secret)
			require.EqualValues(t, 1, calls.Load(), "permanent errors must not be retried")
		})
	}
}

func TestInformerManager_WrappedDiscoveryErrorShowsCauseWithoutURL(t *testing.T) {
	for _, tt := range []struct {
		name  string
		cause error
		want  string
	}{
		{name: "tls", cause: x509.UnknownAuthorityError{}, want: "x509.UnknownAuthorityError"},
		{
			name: "network policy",
			cause: &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{
				Syscall: "connect", Err: syscall.EPERM,
			}},
			want: "operation not permitted",
		},
		{name: "protocol", cause: http.ErrSchemeMismatch, want: "HTTP response to HTTPS client"},
		{name: "unauthorized", cause: apierrors.NewUnauthorized("private response"), want: "HTTP 401"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager, _ := newTestInformerManager(t, map[string]discoveryResourceLister{
				"test": &fakeResourceLister{err: &url.Error{
					Op:  "Get",
					URL: "https://example.invalid/apis",
					Err: tt.cause,
				}},
			})
			wait := runTestInformerManager(t, manager, func(context.Context, string, func() []*model.Workload) {
				t.Error("permanent failure must not reconcile")
			})
			err := wait()
			require.ErrorContains(t, err, tt.want)
			require.NotContains(t, err.Error(), "example.invalid")
			require.NotContains(t, err.Error(), "private response")
		})
	}
}

func availableResources(gv string) (*metav1.APIResourceList, error) {
	resource := "deployments"
	if gv == "nais.io/v1" {
		resource = "naisjobs"
	}
	return &metav1.APIResourceList{
		GroupVersion: gv,
		APIResources: []metav1.APIResource{{Name: resource}},
	}, nil
}

func newTestInformerManager(t *testing.T, listers map[string]discoveryResourceLister) (*InformerManager, map[string]*dynamicfake.FakeDynamicClient) {
	t.Helper()
	original := newDiscoveryClientForConfig
	newDiscoveryClientForConfig = func(cfg *rest.Config) (discoveryResourceLister, error) {
		require.Equal(t, 10*time.Second, cfg.Timeout)
		return listers[strings.TrimPrefix(cfg.Host, "https://")], nil
	}
	t.Cleanup(func() { newDiscoveryClientForConfig = original })

	cfg := config.K8sConfig{}
	for name := range listers {
		cfg.StaticClusters = append(cfg.StaticClusters, config.StaticCluster{Name: name, Host: "https://" + name})
	}
	queue := &WorkloadEventQueue{
		Updated: make(chan *model.Workload, 100),
		Deleted: make(chan *model.Workload, 100),
	}
	manager, err := NewInformerManager(t.Context(), "tenant", cfg, queue, logrus.New())
	require.NoError(t, err)
	t.Cleanup(manager.Stop)
	clients := make(map[string]*dynamicfake.FakeDynamicClient)
	for name, cluster := range manager.clusters {
		client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
			testGVR: "DeploymentList",
			{Group: "nais.io", Version: "v1", Resource: "naisjobs"}: "NaisjobList",
		}, testDeployment("original"))
		cluster.factory = dynamicinformer.NewFilteredDynamicSharedInformerFactory(client, 0, metav1.NamespaceAll, nil)
		clients[name] = client
	}
	return manager, clients
}

func runTestInformerManager(t *testing.T, manager *InformerManager, onReady func(context.Context, string, func() []*model.Workload)) func() error {
	t.Helper()
	done := make(chan struct{})
	var err error
	go func() {
		err = manager.Run(onReady)
		close(done)
	}()
	wait := func() error {
		t.Helper()
		select {
		case <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("informer manager did not stop")
			return nil
		}
	}
	t.Cleanup(func() {
		manager.Stop()
		wait()
	})
	return wait
}

func receiveCluster(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case cluster := <-ch:
		return cluster
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for cluster")
		return ""
	}
}

func testDeployment(tag string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "app", "namespace": "team"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "app", "image": "example/app:" + tag}},
		}}},
	}}
}

func replaceDiscoveryClient(t *testing.T, client discoveryResourceLister) func() {
	t.Helper()
	original := newDiscoveryClientForConfig
	newDiscoveryClientForConfig = func(_ *rest.Config) (discoveryResourceLister, error) {
		return client, nil
	}
	return func() {
		newDiscoveryClientForConfig = original
	}
}
