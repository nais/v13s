# \ComponentPropertyAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateProperty**](ComponentPropertyAPI.md#CreateProperty) | **Put** /v1/component/{uuid}/property | Creates a new component property
[**DeleteProperty**](ComponentPropertyAPI.md#DeleteProperty) | **Delete** /v1/component/{uuid}/property/{propertyUuid} | Deletes a config property
[**GetProperties**](ComponentPropertyAPI.md#GetProperties) | **Get** /v1/component/{uuid}/property | Returns a list of all properties for the specified component



## CreateProperty

> ComponentProperty CreateProperty(ctx, uuid).ComponentProperty(componentProperty).Execute()

Creates a new component property



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to create a property for
	componentProperty := *openapiclient.NewComponentProperty("PropertyType_example", "Uuid_example") // ComponentProperty |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComponentPropertyAPI.CreateProperty(context.Background(), uuid).ComponentProperty(componentProperty).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentPropertyAPI.CreateProperty``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateProperty`: ComponentProperty
	fmt.Fprintf(os.Stdout, "Response from `ComponentPropertyAPI.CreateProperty`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to create a property for | 

### Other Parameters

Other parameters are passed through a pointer to a apiCreatePropertyRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **componentProperty** | [**ComponentProperty**](ComponentProperty.md) |  | 

### Return type

[**ComponentProperty**](ComponentProperty.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteProperty

> DeleteProperty(ctx, uuid, propertyUuid).Execute()

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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to delete a property from
	propertyUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component property to delete

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.ComponentPropertyAPI.DeleteProperty(context.Background(), uuid, propertyUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentPropertyAPI.DeleteProperty``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to delete a property from | 
**propertyUuid** | **string** | The UUID of the component property to delete | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeletePropertyRequest struct via the builder pattern


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


## GetProperties

> []ComponentProperty GetProperties(ctx, uuid).Execute()

Returns a list of all properties for the specified component



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to retrieve properties for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ComponentPropertyAPI.GetProperties(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ComponentPropertyAPI.GetProperties``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProperties`: []ComponentProperty
	fmt.Fprintf(os.Stdout, "Response from `ComponentPropertyAPI.GetProperties`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to retrieve properties for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetPropertiesRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**[]ComponentProperty**](ComponentProperty.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

