# \PermissionAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AddPermissionToTeam**](PermissionAPI.md#AddPermissionToTeam) | **Post** /v1/permission/{permission}/team/{uuid} | Adds the permission to the specified team.
[**AddPermissionToUser**](PermissionAPI.md#AddPermissionToUser) | **Post** /v1/permission/{permission}/user/{username} | Adds the permission to the specified username.
[**GetAllPermissions**](PermissionAPI.md#GetAllPermissions) | **Get** /v1/permission | Returns a list of all permissions
[**RemovePermissionFromTeam**](PermissionAPI.md#RemovePermissionFromTeam) | **Delete** /v1/permission/{permission}/team/{uuid} | Removes the permission from the team.
[**RemovePermissionFromUser**](PermissionAPI.md#RemovePermissionFromUser) | **Delete** /v1/permission/{permission}/user/{username} | Removes the permission from the user.



## AddPermissionToTeam

> Team AddPermissionToTeam(ctx, uuid, permission).Execute()

Adds the permission to the specified team.



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | A valid team uuid
	permission := "permission_example" // string | A valid permission

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.PermissionAPI.AddPermissionToTeam(context.Background(), uuid, permission).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `PermissionAPI.AddPermissionToTeam``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `AddPermissionToTeam`: Team
	fmt.Fprintf(os.Stdout, "Response from `PermissionAPI.AddPermissionToTeam`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | A valid team uuid | 
**permission** | **string** | A valid permission | 

### Other Parameters

Other parameters are passed through a pointer to a apiAddPermissionToTeamRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**Team**](Team.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AddPermissionToUser

> UserPrincipal AddPermissionToUser(ctx, username, permission).Execute()

Adds the permission to the specified username.



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
	username := "username_example" // string | A valid username
	permission := "permission_example" // string | A valid permission

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.PermissionAPI.AddPermissionToUser(context.Background(), username, permission).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `PermissionAPI.AddPermissionToUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `AddPermissionToUser`: UserPrincipal
	fmt.Fprintf(os.Stdout, "Response from `PermissionAPI.AddPermissionToUser`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string** | A valid username | 
**permission** | **string** | A valid permission | 

### Other Parameters

Other parameters are passed through a pointer to a apiAddPermissionToUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**UserPrincipal**](UserPrincipal.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetAllPermissions

> string GetAllPermissions(ctx).Execute()

Returns a list of all permissions



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
	resp, r, err := apiClient.PermissionAPI.GetAllPermissions(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `PermissionAPI.GetAllPermissions``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetAllPermissions`: string
	fmt.Fprintf(os.Stdout, "Response from `PermissionAPI.GetAllPermissions`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetAllPermissionsRequest struct via the builder pattern


### Return type

**string**

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RemovePermissionFromTeam

> Team RemovePermissionFromTeam(ctx, uuid, permission).Execute()

Removes the permission from the team.



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | A valid team uuid
	permission := "permission_example" // string | A valid permission

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.PermissionAPI.RemovePermissionFromTeam(context.Background(), uuid, permission).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `PermissionAPI.RemovePermissionFromTeam``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RemovePermissionFromTeam`: Team
	fmt.Fprintf(os.Stdout, "Response from `PermissionAPI.RemovePermissionFromTeam`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | A valid team uuid | 
**permission** | **string** | A valid permission | 

### Other Parameters

Other parameters are passed through a pointer to a apiRemovePermissionFromTeamRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**Team**](Team.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RemovePermissionFromUser

> UserPrincipal RemovePermissionFromUser(ctx, username, permission).Execute()

Removes the permission from the user.



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
	username := "username_example" // string | A valid username
	permission := "permission_example" // string | A valid permission

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.PermissionAPI.RemovePermissionFromUser(context.Background(), username, permission).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `PermissionAPI.RemovePermissionFromUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RemovePermissionFromUser`: UserPrincipal
	fmt.Fprintf(os.Stdout, "Response from `PermissionAPI.RemovePermissionFromUser`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string** | A valid username | 
**permission** | **string** | A valid permission | 

### Other Parameters

Other parameters are passed through a pointer to a apiRemovePermissionFromUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**UserPrincipal**](UserPrincipal.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

