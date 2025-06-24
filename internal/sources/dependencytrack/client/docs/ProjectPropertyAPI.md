# \ProjectPropertyAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateProperty1**](ProjectPropertyAPI.md#CreateProperty1) | **Put** /v1/project/{uuid}/property | Creates a new project property
[**DeleteProperty1**](ProjectPropertyAPI.md#DeleteProperty1) | **Delete** /v1/project/{uuid}/property | Deletes a config property
[**GetProperties1**](ProjectPropertyAPI.md#GetProperties1) | **Get** /v1/project/{uuid}/property | Returns a list of all ProjectProperties for the specified project
[**UpdateProperty**](ProjectPropertyAPI.md#UpdateProperty) | **Post** /v1/project/{uuid}/property | Updates a project property



## CreateProperty1

> ProjectProperty CreateProperty1(ctx, uuid).ProjectProperty(projectProperty).Execute()

Creates a new project property



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to create a property for
	projectProperty := *openapiclient.NewProjectProperty("PropertyType_example") // ProjectProperty |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectPropertyAPI.CreateProperty1(context.Background(), uuid).ProjectProperty(projectProperty).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectPropertyAPI.CreateProperty1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateProperty1`: ProjectProperty
	fmt.Fprintf(os.Stdout, "Response from `ProjectPropertyAPI.CreateProperty1`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to create a property for | 

### Other Parameters

Other parameters are passed through a pointer to a apiCreateProperty1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **projectProperty** | [**ProjectProperty**](ProjectProperty.md) |  | 

### Return type

[**ProjectProperty**](ProjectProperty.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteProperty1

> DeleteProperty1(ctx, uuid).ProjectProperty(projectProperty).Execute()

Deletes a config property



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to delete a property from
	projectProperty := *openapiclient.NewProjectProperty("PropertyType_example") // ProjectProperty |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.ProjectPropertyAPI.DeleteProperty1(context.Background(), uuid).ProjectProperty(projectProperty).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectPropertyAPI.DeleteProperty1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to delete a property from | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteProperty1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **projectProperty** | [**ProjectProperty**](ProjectProperty.md) |  | 

### Return type

 (empty response body)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProperties1

> []ProjectProperty GetProperties1(ctx, uuid).Execute()

Returns a list of all ProjectProperties for the specified project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to retrieve properties for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectPropertyAPI.GetProperties1(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectPropertyAPI.GetProperties1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProperties1`: []ProjectProperty
	fmt.Fprintf(os.Stdout, "Response from `ProjectPropertyAPI.GetProperties1`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to retrieve properties for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProperties1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**[]ProjectProperty**](ProjectProperty.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateProperty

> ProjectProperty UpdateProperty(ctx, uuid).ProjectProperty(projectProperty).Execute()

Updates a project property



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to create a property for
	projectProperty := *openapiclient.NewProjectProperty("PropertyType_example") // ProjectProperty |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectPropertyAPI.UpdateProperty(context.Background(), uuid).ProjectProperty(projectProperty).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectPropertyAPI.UpdateProperty``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateProperty`: ProjectProperty
	fmt.Fprintf(os.Stdout, "Response from `ProjectPropertyAPI.UpdateProperty`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to create a property for | 

### Other Parameters

Other parameters are passed through a pointer to a apiUpdatePropertyRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **projectProperty** | [**ProjectProperty**](ProjectProperty.md) |  | 

### Return type

[**ProjectProperty**](ProjectProperty.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

