# \PolicyConditionAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreatePolicyCondition**](PolicyConditionAPI.md#CreatePolicyCondition) | **Put** /v1/policy/{uuid}/condition | Creates a new policy condition
[**DeletePolicyCondition**](PolicyConditionAPI.md#DeletePolicyCondition) | **Delete** /v1/policy/condition/{uuid} | Deletes a policy condition
[**UpdatePolicyCondition**](PolicyConditionAPI.md#UpdatePolicyCondition) | **Post** /v1/policy/condition | Updates a policy condition



## CreatePolicyCondition

> PolicyCondition CreatePolicyCondition(ctx, uuid).PolicyCondition(policyCondition).Execute()

Creates a new policy condition



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the policy
	policyCondition := *openapiclient.NewPolicyCondition("Uuid_example") // PolicyCondition |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.PolicyConditionAPI.CreatePolicyCondition(context.Background(), uuid).PolicyCondition(policyCondition).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `PolicyConditionAPI.CreatePolicyCondition``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreatePolicyCondition`: PolicyCondition
	fmt.Fprintf(os.Stdout, "Response from `PolicyConditionAPI.CreatePolicyCondition`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the policy | 

### Other Parameters

Other parameters are passed through a pointer to a apiCreatePolicyConditionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **policyCondition** | [**PolicyCondition**](PolicyCondition.md) |  | 

### Return type

[**PolicyCondition**](PolicyCondition.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeletePolicyCondition

> DeletePolicyCondition(ctx, uuid).Execute()

Deletes a policy condition



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the policy condition to delete

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.PolicyConditionAPI.DeletePolicyCondition(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `PolicyConditionAPI.DeletePolicyCondition``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the policy condition to delete | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeletePolicyConditionRequest struct via the builder pattern


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


## UpdatePolicyCondition

> PolicyCondition UpdatePolicyCondition(ctx).PolicyCondition(policyCondition).Execute()

Updates a policy condition



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
	policyCondition := *openapiclient.NewPolicyCondition("Uuid_example") // PolicyCondition |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.PolicyConditionAPI.UpdatePolicyCondition(context.Background()).PolicyCondition(policyCondition).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `PolicyConditionAPI.UpdatePolicyCondition``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdatePolicyCondition`: PolicyCondition
	fmt.Fprintf(os.Stdout, "Response from `PolicyConditionAPI.UpdatePolicyCondition`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdatePolicyConditionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **policyCondition** | [**PolicyCondition**](PolicyCondition.md) |  | 

### Return type

[**PolicyCondition**](PolicyCondition.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

