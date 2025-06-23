# \DependencyGraphAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetComponentsAndServicesByComponentUuid**](DependencyGraphAPI.md#GetComponentsAndServicesByComponentUuid) | **Get** /v1/dependencyGraph/component/{uuid}/directDependencies | Returns a list of specific components and services from component UUID
[**GetComponentsAndServicesByProjectUuid**](DependencyGraphAPI.md#GetComponentsAndServicesByProjectUuid) | **Get** /v1/dependencyGraph/project/{uuid}/directDependencies | Returns a list of specific components and services from project UUID



## GetComponentsAndServicesByComponentUuid

> []DependencyGraphResponse GetComponentsAndServicesByComponentUuid(ctx, uuid).Execute()

Returns a list of specific components and services from component UUID



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID"
)

func main() {
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DependencyGraphAPI.GetComponentsAndServicesByComponentUuid(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DependencyGraphAPI.GetComponentsAndServicesByComponentUuid``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComponentsAndServicesByComponentUuid`: []DependencyGraphResponse
	fmt.Fprintf(os.Stdout, "Response from `DependencyGraphAPI.GetComponentsAndServicesByComponentUuid`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetComponentsAndServicesByComponentUuidRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**[]DependencyGraphResponse**](DependencyGraphResponse.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetComponentsAndServicesByProjectUuid

> []DependencyGraphResponse GetComponentsAndServicesByProjectUuid(ctx, uuid).Execute()

Returns a list of specific components and services from project UUID



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID"
)

func main() {
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.DependencyGraphAPI.GetComponentsAndServicesByProjectUuid(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `DependencyGraphAPI.GetComponentsAndServicesByProjectUuid``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComponentsAndServicesByProjectUuid`: []DependencyGraphResponse
	fmt.Fprintf(os.Stdout, "Response from `DependencyGraphAPI.GetComponentsAndServicesByProjectUuid`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetComponentsAndServicesByProjectUuidRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**[]DependencyGraphResponse**](DependencyGraphResponse.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

