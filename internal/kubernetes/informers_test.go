package kubernetes

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeResourceLister stands in for discovery.DiscoveryInterface in tests.
type fakeResourceLister struct {
	err     error
	resList *metav1.APIResourceList
}

func (f *fakeResourceLister) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
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
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		t.Fatalf("expected *oauth2.RetrieveError, got %v", err)
	}
}
