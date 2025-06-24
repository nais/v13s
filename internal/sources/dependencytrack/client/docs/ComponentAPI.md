# \ComponentAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateComponent**](ComponentAPI.md#CreateComponent) | **Put** /v1/component/project/{uuid} | Creates a new component
[**DeleteComponent**](ComponentAPI.md#DeleteComponent) | **Delete** /v1/component/{uuid} | Deletes a component
[**GetAllComponents**](ComponentAPI.md#GetAllComponents) | **Get** /v1/component/project/{uuid} | Returns a list of all components for a given project
[**GetComponentByHash**](ComponentAPI.md#GetComponentByHash) | **Get** /v1/component/hash/{hash} | Returns a list of components that have the specified hash value
[**GetComponentByIdentity**](ComponentAPI.md#GetComponentByIdentity) | **Get** /v1/component/identity | Returns a list of components that have the specified component identity. This resource accepts coordinates (group, name, version) or purl, cpe, or swidTagId
[**GetComponentByUuid**](ComponentAPI.md#GetComponentByUuid) | **Get** /v1/component/{uuid} | Returns a specific component
[**GetDependencyGraphForComponent**](ComponentAPI.md#GetDependencyGraphForComponent) | **Get** /v1/component/project/{projectUuid}/dependencyGraph/{componentUuids} | Returns the expanded dependency graph to every occurrence of a component
[**IdentifyInternalComponents**](ComponentAPI.md#IdentifyInternalComponents) | **Get** /v1/component/internal/identify | Requests the identification of internal components in the portfolio
[**UpdateComponent**](ComponentAPI.md#UpdateComponent) | **Post** /v1/component | Updates a component



## CreateComponent

> Component CreateComponent(ctx, uuid).Component(component).Execute()

Creates a new component



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to create a component for
	component := *openapiclient.NewComponent("Classifier_example", *openapiclient.NewProject("Uuid_example", int64(123)), "Uuid_example") // Component |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComponentAPI.CreateComponent(context.Background(), uuid).Component(component).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentAPI.CreateComponent``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateComponent`: Component
	fmt.Fprintf(os.Stdout, "Response from `ComponentAPI.CreateComponent`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to create a component for | 

### Other Parameters

Other parameters are passed through a pointer to a apiCreateComponentRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **component** | [**Component**](Component.md) |  | 

### Return type

[**Component**](Component.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteComponent

> DeleteComponent(ctx, uuid).Execute()

Deletes a component



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to delete

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.ComponentAPI.DeleteComponent(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentAPI.DeleteComponent``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to delete | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteComponentRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

 (empty response body)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetAllComponents

> []Component GetAllComponents(ctx, uuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).OnlyOutdated(onlyOutdated).OnlyDirect(onlyDirect).Execute()

Returns a list of all components for a given project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to retrieve components for
	pageNumber := "pageNumber_example" // string | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to "1")
	pageSize := "pageSize_example" // string | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to "100")
	offset := "offset_example" // string | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := "limit_example" // string | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)
	onlyOutdated := true // bool | Optionally exclude recent components so only outdated components are returned (optional)
	onlyDirect := true // bool | Optionally exclude transitive dependencies so only direct dependencies are returned (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComponentAPI.GetAllComponents(context.Background(), uuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).OnlyOutdated(onlyOutdated).OnlyDirect(onlyDirect).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentAPI.GetAllComponents``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetAllComponents`: []Component
	fmt.Fprintf(os.Stdout, "Response from `ComponentAPI.GetAllComponents`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to retrieve components for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetAllComponentsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **pageNumber** | **string** | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to &quot;1&quot;]
 **pageSize** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to &quot;100&quot;]
 **offset** | **string** | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 
 **onlyOutdated** | **bool** | Optionally exclude recent components so only outdated components are returned | 
 **onlyDirect** | **bool** | Optionally exclude transitive dependencies so only direct dependencies are returned | 

### Return type

[**[]Component**](Component.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetComponentByHash

> []Component GetComponentByHash(ctx, hash).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of components that have the specified hash value



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
	hash := "hash_example" // string | The MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, or BLAKE3 hash of the component to retrieve
	pageNumber := "pageNumber_example" // string | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to "1")
	pageSize := "pageSize_example" // string | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to "100")
	offset := "offset_example" // string | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := "limit_example" // string | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComponentAPI.GetComponentByHash(context.Background(), hash).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentAPI.GetComponentByHash``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComponentByHash`: []Component
	fmt.Fprintf(os.Stdout, "Response from `ComponentAPI.GetComponentByHash`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**hash** | **string** | The MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, or BLAKE3 hash of the component to retrieve | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetComponentByHashRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **pageNumber** | **string** | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to &quot;1&quot;]
 **pageSize** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to &quot;100&quot;]
 **offset** | **string** | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]Component**](Component.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetComponentByIdentity

> []Component GetComponentByIdentity(ctx).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Group(group).Name(name).Version(version).Purl(purl).Cpe(cpe).SwidTagId(swidTagId).Project(project).Execute()

Returns a list of components that have the specified component identity. This resource accepts coordinates (group, name, version) or purl, cpe, or swidTagId



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
	pageNumber := "pageNumber_example" // string | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to "1")
	pageSize := "pageSize_example" // string | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to "100")
	offset := "offset_example" // string | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := "limit_example" // string | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)
	group := "group_example" // string | The group of the component (optional)
	name := "name_example" // string | The name of the component (optional)
	version := "version_example" // string | The version of the component (optional)
	purl := "purl_example" // string | The purl of the component (optional)
	cpe := "cpe_example" // string | The cpe of the component (optional)
	swidTagId := "swidTagId_example" // string | The swidTagId of the component (optional)
	project := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The project the component belongs to (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComponentAPI.GetComponentByIdentity(context.Background()).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Group(group).Name(name).Version(version).Purl(purl).Cpe(cpe).SwidTagId(swidTagId).Project(project).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentAPI.GetComponentByIdentity``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComponentByIdentity`: []Component
	fmt.Fprintf(os.Stdout, "Response from `ComponentAPI.GetComponentByIdentity`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetComponentByIdentityRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **pageNumber** | **string** | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to &quot;1&quot;]
 **pageSize** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to &quot;100&quot;]
 **offset** | **string** | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 
 **group** | **string** | The group of the component | 
 **name** | **string** | The name of the component | 
 **version** | **string** | The version of the component | 
 **purl** | **string** | The purl of the component | 
 **cpe** | **string** | The cpe of the component | 
 **swidTagId** | **string** | The swidTagId of the component | 
 **project** | **string** | The project the component belongs to | 

### Return type

[**[]Component**](Component.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetComponentByUuid

> Component GetComponentByUuid(ctx, uuid).IncludeRepositoryMetaData(includeRepositoryMetaData).Execute()

Returns a specific component



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to retrieve
	includeRepositoryMetaData := true // bool | Optionally includes third-party metadata about the component from external repositories (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComponentAPI.GetComponentByUuid(context.Background(), uuid).IncludeRepositoryMetaData(includeRepositoryMetaData).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentAPI.GetComponentByUuid``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComponentByUuid`: Component
	fmt.Fprintf(os.Stdout, "Response from `ComponentAPI.GetComponentByUuid`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to retrieve | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetComponentByUuidRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **includeRepositoryMetaData** | **bool** | Optionally includes third-party metadata about the component from external repositories | 

### Return type

[**Component**](Component.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetDependencyGraphForComponent

> map[string]interface{} GetDependencyGraphForComponent(ctx, projectUuid, componentUuids).Execute()

Returns the expanded dependency graph to every occurrence of a component



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
	projectUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to get the expanded dependency graph for
	componentUuids := "componentUuids_example" // string | List of UUIDs of the components (separated by |) to get the expanded dependency graph for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComponentAPI.GetDependencyGraphForComponent(context.Background(), projectUuid, componentUuids).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentAPI.GetDependencyGraphForComponent``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetDependencyGraphForComponent`: map[string]interface{}
	fmt.Fprintf(os.Stdout, "Response from `ComponentAPI.GetDependencyGraphForComponent`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**projectUuid** | **string** | The UUID of the project to get the expanded dependency graph for | 
**componentUuids** | **string** | List of UUIDs of the components (separated by |) to get the expanded dependency graph for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetDependencyGraphForComponentRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

**map[string]interface{}**

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## IdentifyInternalComponents

> IdentifyInternalComponents(ctx).Execute()

Requests the identification of internal components in the portfolio



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

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.ComponentAPI.IdentifyInternalComponents(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentAPI.IdentifyInternalComponents``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiIdentifyInternalComponentsRequest struct via the builder pattern


### Return type

 (empty response body)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateComponent

> Component UpdateComponent(ctx).Component(component).Execute()

Updates a component



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
	component := *openapiclient.NewComponent("Classifier_example", *openapiclient.NewProject("Uuid_example", int64(123)), "Uuid_example") // Component |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComponentAPI.UpdateComponent(context.Background()).Component(component).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentAPI.UpdateComponent``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateComponent`: Component
	fmt.Fprintf(os.Stdout, "Response from `ComponentAPI.UpdateComponent`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateComponentRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **component** | [**Component**](Component.md) |  | 

### Return type

[**Component**](Component.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

