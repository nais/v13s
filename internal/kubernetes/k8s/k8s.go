package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/log"
	nais_io_v1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/v13s/internal/config"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func add(obj any) {
	//	log.WithField("object", obj).Info("Object added")
}
func update(oldObj, newObj any) {

	//	log.WithField("object", newObj).Info("Object updated")
}

func delete(obj any) {
	//	log.WithField("object", obj).Info("Object deleted")

}

func Informers(ctx context.Context, cfg config.ClusterConfigMap, log *logrus.Entry) error {
	for cluster, config := range cfg {
		log.Infof("cluster: %s, config: %v", cluster, config)
		// Create a new Kubernetes client
		k8sClient, err := kubernetes.NewForConfig(config)
		if err != nil {
			return err
		}
		dynamicClient, err := dynamic.NewForConfig(config)
		if err != nil {
			return err
		}
		err = startInformers(ctx, k8sClient, dynamicClient, "", log)
		if err != nil {
			return fmt.Errorf("start informers: %w", err)
		}
		log.Infof("started informers for cluster: %s", cluster)

	}
	return nil
}

type Cluster string

type Manager struct {
	watchers map[Cluster]cache.SharedIndexInformer
}

type Watcher struct {
	cluster       Cluster
	informer      cache.SharedIndexInformer
	client        kubernetes.Interface
	dynamicClient dynamic.Interface
	log           logrus.FieldLogger
}

func startInformers(
	ctx context.Context,
	k8sClient *kubernetes.Clientset,
	dynamicClient *dynamic.DynamicClient,
	namespace string,
	log *log.Entry,
) error {
	log.Infof("setting up informer(s) with %d-hours interval for re-listing of resources", 4)

	ticker := time.NewTicker(4 * time.Hour)
	defer ticker.Stop()

	for {
		// Create a new context for each informer restart
		informerCtx, cancel := context.WithCancel(ctx)

		// Recreate the informer factory and set up the informers
		slsaInformers := prepareInformers(informerCtx, k8sClient, dynamicClient, namespace, log)
		for name, informer := range slsaInformers {
			l := log.WithField("resource", name)
			//err := informer.SetWatchErrorHandler(cache.DefaultWatchErrorHandler)
			err := informer.SetWatchErrorHandler(func(r *cache.Reflector, err error) {
				if err != nil && strings.Contains(err.Error(), "stream error: stream ID") && strings.Contains(err.Error(), "NO_ERROR; received from peer") {
					// Suppress this warning
					fmt.Println("***** yolololo")
					return
				}
				fmt.Println("***** error: ", err)
				cache.DefaultWatchErrorHandler(r, err)
			})

			if err != nil {
				cancel()
				return fmt.Errorf("set watch error handler: %w", err)
			}

			l.Info("setting up monitor for resource")
			_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
				AddFunc:    add,
				UpdateFunc: update,
				DeleteFunc: delete,
			})
			if err != nil {
				cancel()
				return fmt.Errorf("add event handler: %w", err)
			}

			go informer.Run(informerCtx.Done())
			if !cache.WaitForCacheSync(informerCtx.Done(), informer.HasSynced) {
				//runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
				cancel()
				return fmt.Errorf("timed out waiting for caches to sync")
			}

			l.Infof("informer cache synced: %v", informer.HasSynced())
		}

		// Wait for ticker or context cancellation
		select {
		case <-ticker.C:
			log.Infof("Restarting informers after %d-hour interval", 4)
			cancel() // Stop the current informers
		case <-ctx.Done():
			cancel()
			return nil
		}
	}
}

type SlsaInformers map[string]cache.SharedIndexInformer

func prepareInformers(ctx context.Context, k8sClient *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, namespace string, logger *log.Entry) SlsaInformers {
	logger.Info("prepare informer(s)")
	// default ignore system namespaces
	switch namespace {
	case "":
		namespace = "metadata.namespace!=kube-system," +
			"metadata.namespace!=kube-public," +
			"metadata.namespace!=cnrm-system," +
			"metadata.namespace!=kyverno," +
			"metadata.namespace!=linkerd"
	default:
		namespace = "metadata.namespace=" + namespace
	}

	tweakListOpts := informers.WithTweakListOptions(
		func(options *v1.ListOptions) {
			options.FieldSelector = namespace
		})
	dynTweakListOpts := dynamicinformer.TweakListOptionsFunc(
		func(options *v1.ListOptions) {
			options.FieldSelector = namespace
		})
	factory := informers.NewSharedInformerFactoryWithOptions(k8sClient, 1*time.Hour, tweakListOpts)
	dinf := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, 1*time.Hour, "", dynTweakListOpts)

	infs := SlsaInformers{
		"deployment": factory.Apps().V1().Deployments().Informer(),
	}

	_, err := dynamicClient.Resource(nais_io_v1.GroupVersion.WithResource("naisjobs")).List(ctx, v1.ListOptions{})
	if err != nil {
		logger.Info("could not list naisjobs, skipping informer setup for naisjobs, " + err.Error())
	} else {
		infs["naisjobs"] = dinf.ForResource(nais_io_v1.GroupVersion.WithResource("naisjobs")).Informer()
	}

	return infs
}
