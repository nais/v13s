package k8s_new

import (
	"github.com/nais/v13s/internal/model"
	v1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type WorkloadEventHandler interface {
	GetWorkloads(cluster string, obj *unstructured.Unstructured) []*model.Workload
	GetGVR() schema.GroupVersionResource
}

type DeploymentHandler struct {
	gvr schema.GroupVersionResource
}

func (d *DeploymentHandler) GetGVR() schema.GroupVersionResource {
	return d.gvr
}

func (d *DeploymentHandler) GetWorkloads(cluster string, obj *unstructured.Unstructured) []*model.Workload {
	deploy := &v1.Deployment{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, deploy)
	if err != nil {
		return nil
	}
	return []*model.Workload{}
}

func NewDeploymentHandler() WorkloadEventHandler {
	return &DeploymentHandler{
		gvr: schema.GroupVersionResource{
			Group:    "apps",
			Version:  "v1",
			Resource: "deployments",
		},
	}
}
