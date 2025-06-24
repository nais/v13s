# \OidcAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AddMapping2**](OidcAPI.md#AddMapping2) | **Put** /v1/oidc/mapping | Adds a mapping
[**CreateGroup**](OidcAPI.md#CreateGroup) | **Put** /v1/oidc/group | Creates group
[**DeleteGroup**](OidcAPI.md#DeleteGroup) | **Delete** /v1/oidc/group/{uuid} | Deletes a group
[**DeleteMapping2**](OidcAPI.md#DeleteMapping2) | **Delete** /v1/oidc/group/{groupUuid}/team/{teamUuid}/mapping | Deletes a mapping
[**DeleteMappingByUuid**](OidcAPI.md#DeleteMappingByUuid) | **Delete** /v1/oidc/mapping/{uuid} | Deletes a mapping
[**IsAvailable**](OidcAPI.md#IsAvailable) | **Get** /v1/oidc/available | Indicates if OpenID Connect is available for this application
[**RetrieveGroups**](OidcAPI.md#RetrieveGroups) | **Get** /v1/oidc/group | Returns a list of all groups
[**RetrieveTeamsMappedToGroup**](OidcAPI.md#RetrieveTeamsMappedToGroup) | **Get** /v1/oidc/group/{uuid}/team | Returns a list of teams associated with the specified group
[**UpdateGroup**](OidcAPI.md#UpdateGroup) | **Post** /v1/oidc/group | Updates group



## AddMapping2

> MappedOidcGroup AddMapping2(ctx).MappedOidcGroupRequest(mappedOidcGroupRequest).Execute()

Adds a mapping



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
	mappedOidcGroupRequest := *openapiclient.NewMappedOidcGroupRequest("Team_example", "Group_example") // MappedOidcGroupRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.OidcAPI.AddMapping2(context.Background()).MappedOidcGroupRequest(mappedOidcGroupRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `OidcAPI.AddMapping2``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `AddMapping2`: MappedOidcGroup
	fmt.Fprintf(os.Stdout, "Response from `OidcAPI.AddMapping2`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAddMapping2Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **mappedOidcGroupRequest** | [**MappedOidcGroupRequest**](MappedOidcGroupRequest.md) |  | 

### Return type

[**MappedOidcGroup**](MappedOidcGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CreateGroup

> OidcGroup CreateGroup(ctx).OidcGroup(oidcGroup).Execute()

Creates group



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
	oidcGroup := *openapiclient.NewOidcGroup("Uuid_example") // OidcGroup |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.OidcAPI.CreateGroup(context.Background()).OidcGroup(oidcGroup).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `OidcAPI.CreateGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateGroup`: OidcGroup
	fmt.Fprintf(os.Stdout, "Response from `OidcAPI.CreateGroup`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCreateGroupRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **oidcGroup** | [**OidcGroup**](OidcGroup.md) |  | 

### Return type

[**OidcGroup**](OidcGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteGroup

> DeleteGroup(ctx, uuid).Execute()

Deletes a group



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the group to delete

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.OidcAPI.DeleteGroup(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `OidcAPI.DeleteGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the group to delete | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteGroupRequest struct via the builder pattern


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


## DeleteMapping2

> DeleteMapping2(ctx, groupUuid, teamUuid).Execute()

Deletes a mapping



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
	groupUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the group to delete a mapping for
	teamUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the team to delete a mapping for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.OidcAPI.DeleteMapping2(context.Background(), groupUuid, teamUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `OidcAPI.DeleteMapping2``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**groupUuid** | **string** | The UUID of the group to delete a mapping for | 
**teamUuid** | **string** | The UUID of the team to delete a mapping for | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteMapping2Request struct via the builder pattern


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


## DeleteMappingByUuid

> DeleteMappingByUuid(ctx, uuid).Execute()

Deletes a mapping



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the mapping to delete

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.OidcAPI.DeleteMappingByUuid(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `OidcAPI.DeleteMappingByUuid``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the mapping to delete | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteMappingByUuidRequest struct via the builder pattern


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


## IsAvailable

> bool IsAvailable(ctx).Execute()

Indicates if OpenID Connect is available for this application

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
	resp, r, err := apiClient.OidcAPI.IsAvailable(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `OidcAPI.IsAvailable``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `IsAvailable`: bool
	fmt.Fprintf(os.Stdout, "Response from `OidcAPI.IsAvailable`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiIsAvailableRequest struct via the builder pattern


### Return type

**bool**

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/plain

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RetrieveGroups

> []OidcGroup RetrieveGroups(ctx).Execute()

Returns a list of all groups



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
	resp, r, err := apiClient.OidcAPI.RetrieveGroups(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `OidcAPI.RetrieveGroups``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RetrieveGroups`: []OidcGroup
	fmt.Fprintf(os.Stdout, "Response from `OidcAPI.RetrieveGroups`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiRetrieveGroupsRequest struct via the builder pattern


### Return type

[**[]OidcGroup**](OidcGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RetrieveTeamsMappedToGroup

> []Team RetrieveTeamsMappedToGroup(ctx, uuid).Execute()

Returns a list of teams associated with the specified group



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the mapping to retrieve the team for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.OidcAPI.RetrieveTeamsMappedToGroup(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `OidcAPI.RetrieveTeamsMappedToGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RetrieveTeamsMappedToGroup`: []Team
	fmt.Fprintf(os.Stdout, "Response from `OidcAPI.RetrieveTeamsMappedToGroup`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the mapping to retrieve the team for | 

### Other Parameters

Other parameters are passed through a pointer to a apiRetrieveTeamsMappedToGroupRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**[]Team**](Team.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateGroup

> OidcGroup UpdateGroup(ctx).OidcGroup(oidcGroup).Execute()

Updates group



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
	oidcGroup := *openapiclient.NewOidcGroup("Uuid_example") // OidcGroup |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.OidcAPI.UpdateGroup(context.Background()).OidcGroup(oidcGroup).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `OidcAPI.UpdateGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateGroup`: OidcGroup
	fmt.Fprintf(os.Stdout, "Response from `OidcAPI.UpdateGroup`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateGroupRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **oidcGroup** | [**OidcGroup**](OidcGroup.md) |  | 

### Return type

[**OidcGroup**](OidcGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

