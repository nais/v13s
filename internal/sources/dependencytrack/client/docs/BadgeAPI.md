# \BadgeAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetProjectPolicyViolationsBadge**](BadgeAPI.md#GetProjectPolicyViolationsBadge) | **Get** /v1/badge/violations/project/{uuid} | Returns a policy violations badge for a specific project
[**GetProjectPolicyViolationsBadge1**](BadgeAPI.md#GetProjectPolicyViolationsBadge1) | **Get** /v1/badge/violations/project/{name}/{version} | Returns a policy violations badge for a specific project
[**GetProjectVulnerabilitiesBadge**](BadgeAPI.md#GetProjectVulnerabilitiesBadge) | **Get** /v1/badge/vulns/project/{uuid} | Returns current metrics for a specific project
[**GetProjectVulnerabilitiesBadge1**](BadgeAPI.md#GetProjectVulnerabilitiesBadge1) | **Get** /v1/badge/vulns/project/{name}/{version} | Returns current metrics for a specific project



## GetProjectPolicyViolationsBadge

> string GetProjectPolicyViolationsBadge(ctx, uuid).Execute()

Returns a policy violations badge for a specific project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to retrieve a badge for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.BadgeAPI.GetProjectPolicyViolationsBadge(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `BadgeAPI.GetProjectPolicyViolationsBadge``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectPolicyViolationsBadge`: string
	fmt.Fprintf(os.Stdout, "Response from `BadgeAPI.GetProjectPolicyViolationsBadge`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to retrieve a badge for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectPolicyViolationsBadgeRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

**string**

### Authorization

[ApiKeyQueryAuth](../README.md#ApiKeyQueryAuth), [ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: image/svg+xml

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectPolicyViolationsBadge1

> string GetProjectPolicyViolationsBadge1(ctx, name, version).Execute()

Returns a policy violations badge for a specific project



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
	name := "name_example" // string | The name of the project to query on
	version := "version_example" // string | The version of the project to query on

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.BadgeAPI.GetProjectPolicyViolationsBadge1(context.Background(), name, version).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `BadgeAPI.GetProjectPolicyViolationsBadge1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectPolicyViolationsBadge1`: string
	fmt.Fprintf(os.Stdout, "Response from `BadgeAPI.GetProjectPolicyViolationsBadge1`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**name** | **string** | The name of the project to query on | 
**version** | **string** | The version of the project to query on | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectPolicyViolationsBadge1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

**string**

### Authorization

[ApiKeyQueryAuth](../README.md#ApiKeyQueryAuth), [ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: image/svg+xml

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectVulnerabilitiesBadge

> string GetProjectVulnerabilitiesBadge(ctx, uuid).Execute()

Returns current metrics for a specific project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to retrieve metrics for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.BadgeAPI.GetProjectVulnerabilitiesBadge(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `BadgeAPI.GetProjectVulnerabilitiesBadge``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectVulnerabilitiesBadge`: string
	fmt.Fprintf(os.Stdout, "Response from `BadgeAPI.GetProjectVulnerabilitiesBadge`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to retrieve metrics for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectVulnerabilitiesBadgeRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

**string**

### Authorization

[ApiKeyQueryAuth](../README.md#ApiKeyQueryAuth), [ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: image/svg+xml

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectVulnerabilitiesBadge1

> string GetProjectVulnerabilitiesBadge1(ctx, name, version).Execute()

Returns current metrics for a specific project



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
	name := "name_example" // string | The name of the project to query on
	version := "version_example" // string | The version of the project to query on

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.BadgeAPI.GetProjectVulnerabilitiesBadge1(context.Background(), name, version).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `BadgeAPI.GetProjectVulnerabilitiesBadge1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectVulnerabilitiesBadge1`: string
	fmt.Fprintf(os.Stdout, "Response from `BadgeAPI.GetProjectVulnerabilitiesBadge1`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**name** | **string** | The name of the project to query on | 
**version** | **string** | The version of the project to query on | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectVulnerabilitiesBadge1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

**string**

### Authorization

[ApiKeyQueryAuth](../README.md#ApiKeyQueryAuth), [ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: image/svg+xml

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

