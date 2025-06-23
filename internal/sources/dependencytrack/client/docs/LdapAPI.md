# \LdapAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AddMapping1**](LdapAPI.md#AddMapping1) | **Put** /v1/ldap/mapping | Adds a mapping
[**DeleteMapping1**](LdapAPI.md#DeleteMapping1) | **Delete** /v1/ldap/mapping/{uuid} | Removes a mapping
[**RetrieveLdapGroups**](LdapAPI.md#RetrieveLdapGroups) | **Get** /v1/ldap/groups | Returns the DNs of all accessible groups within the directory
[**RetrieveLdapGroups1**](LdapAPI.md#RetrieveLdapGroups1) | **Get** /v1/ldap/team/{uuid} | Returns the DNs of all groups mapped to the specified team



## AddMapping1

> MappedLdapGroup AddMapping1(ctx).MappedLdapGroupRequest(mappedLdapGroupRequest).Execute()

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
	mappedLdapGroupRequest := *openapiclient.NewMappedLdapGroupRequest("Team_example", "Dn_example") // MappedLdapGroupRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.LdapAPI.AddMapping1(context.Background()).MappedLdapGroupRequest(mappedLdapGroupRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LdapAPI.AddMapping1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `AddMapping1`: MappedLdapGroup
	fmt.Fprintf(os.Stdout, "Response from `LdapAPI.AddMapping1`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAddMapping1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **mappedLdapGroupRequest** | [**MappedLdapGroupRequest**](MappedLdapGroupRequest.md) |  | 

### Return type

[**MappedLdapGroup**](MappedLdapGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteMapping1

> DeleteMapping1(ctx, uuid).Execute()

Removes a mapping



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
	r, err := apiClient.LdapAPI.DeleteMapping1(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LdapAPI.DeleteMapping1``: %v\n", err)
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

Other parameters are passed through a pointer to a apiDeleteMapping1Request struct via the builder pattern


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


## RetrieveLdapGroups

> []string RetrieveLdapGroups(ctx).Execute()

Returns the DNs of all accessible groups within the directory



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
	resp, r, err := apiClient.LdapAPI.RetrieveLdapGroups(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LdapAPI.RetrieveLdapGroups``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RetrieveLdapGroups`: []string
	fmt.Fprintf(os.Stdout, "Response from `LdapAPI.RetrieveLdapGroups`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiRetrieveLdapGroupsRequest struct via the builder pattern


### Return type

**[]string**

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RetrieveLdapGroups1

> []MappedLdapGroup RetrieveLdapGroups1(ctx, uuid).Execute()

Returns the DNs of all groups mapped to the specified team



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the team to retrieve mappings for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.LdapAPI.RetrieveLdapGroups1(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LdapAPI.RetrieveLdapGroups1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RetrieveLdapGroups1`: []MappedLdapGroup
	fmt.Fprintf(os.Stdout, "Response from `LdapAPI.RetrieveLdapGroups1`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the team to retrieve mappings for | 

### Other Parameters

Other parameters are passed through a pointer to a apiRetrieveLdapGroups1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**[]MappedLdapGroup**](MappedLdapGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

