# \ServiceAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateService**](ServiceAPI.md#CreateService) | **Put** /v1/service/project/{uuid} | Creates a new service
[**DeleteService**](ServiceAPI.md#DeleteService) | **Delete** /v1/service/{uuid} | Deletes a service
[**GetAllServices**](ServiceAPI.md#GetAllServices) | **Get** /v1/service/project/{uuid} | Returns a list of all services for a given project
[**GetServiceByUuid**](ServiceAPI.md#GetServiceByUuid) | **Get** /v1/service/{uuid} | Returns a specific service
[**UpdateService**](ServiceAPI.md#UpdateService) | **Post** /v1/service | Updates a service



## CreateService

> ServiceComponent CreateService(ctx, uuid).Body(body).Execute()

Creates a new service



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
	body := *openapiclient.NewServiceComponent(*openapiclient.NewProject(), "Uuid_example") // ServiceComponent |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ServiceAPI.CreateService(context.Background(), uuid).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ServiceAPI.CreateService``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateService`: ServiceComponent
	fmt.Fprintf(os.Stdout, "Response from `ServiceAPI.CreateService`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project | 

### Other Parameters

Other parameters are passed through a pointer to a apiCreateServiceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **body** | [**ServiceComponent**](ServiceComponent.md) |  | 

### Return type

[**ServiceComponent**](ServiceComponent.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteService

> DeleteService(ctx, uuid).Execute()

Deletes a service



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the service to delete

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.ServiceAPI.DeleteService(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ServiceAPI.DeleteService``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the service to delete | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteServiceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

 (empty response body)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetAllServices

> []ServiceComponent GetAllServices(ctx, uuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all services for a given project



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
	pageNumber := TODO // interface{} | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to 1)
	pageSize := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to 100)
	offset := TODO // interface{} | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ServiceAPI.GetAllServices(context.Background(), uuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ServiceAPI.GetAllServices``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetAllServices`: []ServiceComponent
	fmt.Fprintf(os.Stdout, "Response from `ServiceAPI.GetAllServices`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetAllServicesRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **pageNumber** | [**interface{}**](interface{}.md) | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to 1]
 **pageSize** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to 100]
 **offset** | [**interface{}**](interface{}.md) | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]ServiceComponent**](ServiceComponent.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetServiceByUuid

> ServiceComponent GetServiceByUuid(ctx, uuid).Execute()

Returns a specific service



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the service to retrieve

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ServiceAPI.GetServiceByUuid(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ServiceAPI.GetServiceByUuid``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetServiceByUuid`: ServiceComponent
	fmt.Fprintf(os.Stdout, "Response from `ServiceAPI.GetServiceByUuid`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the service to retrieve | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetServiceByUuidRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**ServiceComponent**](ServiceComponent.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateService

> ServiceComponent UpdateService(ctx).Body(body).Execute()

Updates a service



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
	body := *openapiclient.NewServiceComponent(*openapiclient.NewProject(), "Uuid_example") // ServiceComponent |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ServiceAPI.UpdateService(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ServiceAPI.UpdateService``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateService`: ServiceComponent
	fmt.Fprintf(os.Stdout, "Response from `ServiceAPI.UpdateService`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateServiceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**ServiceComponent**](ServiceComponent.md) |  | 

### Return type

[**ServiceComponent**](ServiceComponent.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

