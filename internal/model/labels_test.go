package model

import (
	"maps"
	"testing"
)

func TestUserLabels(t *testing.T) {
	input := map[string]string{"owner": "", "app": "demo"}
	got := UserLabels(input)
	if !maps.Equal(got, map[string]string{"owner": ""}) {
		t.Fatalf("UserLabels = %v, want only user labels", got)
	}
	got["owner"] = "changed"
	if input["owner"] != "" {
		t.Fatal("UserLabels must not mutate the informer labels")
	}
}

func TestWorkloadEqualLabels(t *testing.T) {
	a := &Workload{Name: "demo", ImageName: "image", ImageTag: "v1"}
	b := *a
	b.Labels = map[string]string{}
	if !a.Equal(&b) {
		t.Fatal("nil and empty labels must be equal")
	}
	b.Labels["owner"] = ""
	if a.Equal(&b) {
		t.Fatal("adding an empty label must change equality")
	}
	a.Labels = map[string]string{"owner": "team"}
	if a.Equal(&b) {
		t.Fatal("changing a label must change equality")
	}
	b.Labels = nil
	if a.Equal(&b) {
		t.Fatal("removing labels must change equality")
	}
}
