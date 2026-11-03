package kubernetes

import (
	"maps"
	"testing"

	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestWorkloadLabelEvents(t *testing.T) {
	for _, kind := range []string{"Deployment", "Naisjob"} {
		t.Run(kind, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "nais.io/v1", "kind": kind,
				"metadata": map[string]any{
					"name": "demo", "namespace": "ns",
					"labels": map[string]any{"owner": "original", "app": "demo", "team": "ns"},
				},
				"spec": map[string]any{
					"image": "image:v1",
					"template": map[string]any{
						"metadata": map[string]any{"labels": map[string]any{"owner": "pod-template"}},
						"spec":     map[string]any{"containers": []any{map[string]any{"name": "demo", "image": "image:v1"}}},
					},
				},
			}}
			obj.SetResourceVersion("9")
			queue := &WorkloadEventQueue{Updated: make(chan *model.Workload, 1)}
			handler := newEventHandler("cluster", queue, logrus.New())
			handler.OnAdd(obj, true)
			if got := (<-queue.Updated).Labels; !maps.Equal(got, map[string]string{"owner": "original"}) {
				t.Fatalf("initial labels = %v, want Deployment/Naisjob metadata labels", got)
			}
			updated := obj.DeepCopy()
			updated.SetLabels(map[string]string{"owner": "changed"})
			updated.SetResourceVersion("10")
			handler.OnUpdate(obj, updated)
			select {
			case got := <-queue.Updated:
				if got.Labels["owner"] != "changed" || got.ImageTag != "v1" || got.ResourceVersion != "10" {
					t.Fatalf("label-only event = %+v", got)
				}
			default:
				t.Fatal("label-only change must enqueue an update")
			}
			removed := updated.DeepCopy()
			removed.SetLabels(nil)
			removed.SetResourceVersion("11")
			handler.OnUpdate(updated, removed)
			select {
			case got := <-queue.Updated:
				if got.Labels == nil || len(got.Labels) != 0 || got.ResourceVersion != "11" {
					t.Fatalf("removed labels = %v, want empty", got.Labels)
				}
			default:
				t.Fatal("removing labels must enqueue an update")
			}
			handler.OnUpdate(removed, removed.DeepCopy())
			select {
			case got := <-queue.Updated:
				if len(got.Labels) != 0 {
					t.Fatalf("periodic resync labels = %v, want current labels", got.Labels)
				}
			default:
				t.Fatal("periodic resync must enqueue the workload so stale labels are rewritten")
			}
			unchanged := removed.DeepCopy()
			unchanged.SetResourceVersion("12")
			handler.OnUpdate(removed, unchanged)
			select {
			case got := <-queue.Updated:
				t.Fatalf("update without workload changes enqueued %+v", got)
			default:
			}
		})
	}
}

func TestExtractWorkloadsNaisjobUsesObjectName(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "nais.io/v1",
		"kind":       "Naisjob",
		"metadata": map[string]any{
			"name":      "my-job-q2",
			"namespace": "my-team",
			"labels":    map[string]any{"app": "my-job"},
		},
		"spec": map[string]any{
			"image": "my-image:v1",
		},
	}}

	workloads := extractWorkloads("dev", obj)
	if len(workloads) != 1 {
		t.Fatalf("got %d workloads, want 1", len(workloads))
	}

	if workloads[0].Name != "my-job-q2" {
		t.Fatalf("name = %q, want %q", workloads[0].Name, "my-job-q2")
	}
}

func TestImageNameTag(t *testing.T) {
	tests := []struct {
		name          string
		image         string
		wantImageName string
		wantTagName   string
	}{
		{
			name:          "tag only",
			image:         "my-app:v1.2.3",
			wantImageName: "my-app",
			wantTagName:   "v1.2.3",
		},
		{
			name:          "digest only",
			image:         "my-app@sha256:abcdef123456",
			wantImageName: "my-app",
			wantTagName:   "sha256:abcdef123456",
		},
		{
			name:          "tag and digest",
			image:         "my-app:v1.2.3@sha256:abcdef123456",
			wantImageName: "my-app",
			wantTagName:   "v1.2.3@sha256:abcdef123456",
		},
		{
			name:          "nested repository with tag and digest",
			image:         "acme/widgets/frobnicator:v42@sha256:deadbeefcafebabe",
			wantImageName: "acme/widgets/frobnicator",
			wantTagName:   "v42@sha256:deadbeefcafebabe",
		},
		{
			name:          "nested repository with digest only",
			image:         "acme/widgets/frobnicator@sha256:deadbeefcafebabe",
			wantImageName: "acme/widgets/frobnicator",
			wantTagName:   "sha256:deadbeefcafebabe",
		},
		{
			name:          "registry with port and tag",
			image:         "registry.example:5000/my-app:v1.2.3",
			wantImageName: "registry.example:5000/my-app",
			wantTagName:   "v1.2.3",
		},
		{
			name:          "registry with port tag and digest",
			image:         "registry.example:5000/my-app:v1.2.3@sha256:abcdef123456",
			wantImageName: "registry.example:5000/my-app",
			wantTagName:   "v1.2.3@sha256:abcdef123456",
		},
		{
			name:          "image without tag",
			image:         "my-app",
			wantImageName: "my-app",
			wantTagName:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotImageName, gotTagName := imageNameTag(tt.image)

			if gotImageName != tt.wantImageName {
				t.Fatalf("imageName = %q, want %q", gotImageName, tt.wantImageName)
			}

			if gotTagName != tt.wantTagName {
				t.Fatalf("tagName = %q, want %q", gotTagName, tt.wantTagName)
			}
		})
	}
}
