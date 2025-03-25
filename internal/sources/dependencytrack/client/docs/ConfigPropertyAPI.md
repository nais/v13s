# \ConfigPropertyAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetConfigProperties**](ConfigPropertyAPI.md#GetConfigProperties) | **Get** /v1/configProperty | Returns a list of all ConfigProperties for the specified groupName
[**UpdateConfigProperty**](ConfigPropertyAPI.md#UpdateConfigProperty) | **Post** /v1/configProperty/aggregate | Updates an array of config properties
[**UpdateConfigProperty1**](ConfigPropertyAPI.md#UpdateConfigProperty1) | **Post** /v1/configProperty | Updates a config property



## GetConfigProperties

> []ConfigProperty GetConfigProperties(ctx).Execute()

Returns a list of all ConfigProperties for the specified groupName



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
	resp, r, err := apiClient.ConfigPropertyAPI.GetConfigProperties(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ConfigPropertyAPI.GetConfigProperties``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetConfigProperties`: []ConfigProperty
	fmt.Fprintf(os.Stdout, "Response from `ConfigPropertyAPI.GetConfigProperties`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetConfigPropertiesRequest struct via the builder pattern


### Return type

[**[]ConfigProperty**](ConfigProperty.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateConfigProperty

> []ConfigProperty UpdateConfigProperty(ctx).Body(body).Execute()

Updates an array of config properties



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
	body := []openapiclient.ConfigProperty{*openapiclient.NewConfigProperty("PropertyType_example")} // []ConfigProperty |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ConfigPropertyAPI.UpdateConfigProperty(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ConfigPropertyAPI.UpdateConfigProperty``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateConfigProperty`: []ConfigProperty
	fmt.Fprintf(os.Stdout, "Response from `ConfigPropertyAPI.UpdateConfigProperty`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateConfigPropertyRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**[]ConfigProperty**](ConfigProperty.md) |  | 

### Return type

[**[]ConfigProperty**](ConfigProperty.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateConfigProperty1

> ConfigProperty UpdateConfigProperty1(ctx).Body(body).Execute()

Updates a config property



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
	body := *openapiclient.NewConfigProperty("PropertyType_example") // ConfigProperty |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ConfigPropertyAPI.UpdateConfigProperty1(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ConfigPropertyAPI.UpdateConfigProperty1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateConfigProperty1`: ConfigProperty
	fmt.Fprintf(os.Stdout, "Response from `ConfigPropertyAPI.UpdateConfigProperty1`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateConfigProperty1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**ConfigProperty**](ConfigProperty.md) |  | 

### Return type

[**ConfigProperty**](ConfigProperty.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

