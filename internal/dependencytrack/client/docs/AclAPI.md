# \AclAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AddMapping**](AclAPI.md#AddMapping) | **Put** /v1/acl/mapping | Adds an ACL mapping
[**DeleteMapping**](AclAPI.md#DeleteMapping) | **Delete** /v1/acl/mapping/team/{teamUuid}/project/{projectUuid} | Removes an ACL mapping
[**RetrieveProjects**](AclAPI.md#RetrieveProjects) | **Get** /v1/acl/team/{uuid} | Returns the projects assigned to the specified team



## AddMapping

> AclMappingRequest AddMapping(ctx).Body(body).Execute()

Adds an ACL mapping



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
	body := *openapiclient.NewAclMappingRequest("Team_example", "Project_example") // AclMappingRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.AclAPI.AddMapping(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `AclAPI.AddMapping``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `AddMapping`: AclMappingRequest
	fmt.Fprintf(os.Stdout, "Response from `AclAPI.AddMapping`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAddMappingRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**AclMappingRequest**](AclMappingRequest.md) |  | 

### Return type

[**AclMappingRequest**](AclMappingRequest.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteMapping

> DeleteMapping(ctx, teamUuid, projectUuid).Execute()

Removes an ACL mapping



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
	teamUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the team to delete the mapping for
	projectUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to delete the mapping for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.AclAPI.DeleteMapping(context.Background(), teamUuid, projectUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `AclAPI.DeleteMapping``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**teamUuid** | **string** | The UUID of the team to delete the mapping for | 
**projectUuid** | **string** | The UUID of the project to delete the mapping for | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteMappingRequest struct via the builder pattern


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


## RetrieveProjects

> []string RetrieveProjects(ctx, uuid).ExcludeInactive(excludeInactive).OnlyRoot(onlyRoot).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns the projects assigned to the specified team



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
	excludeInactive := true // bool | Optionally excludes inactive projects from being returned (optional)
	onlyRoot := true // bool | Optionally excludes children projects from being returned (optional)
	pageNumber := TODO // interface{} | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to 1)
	pageSize := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to 100)
	offset := TODO // interface{} | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.AclAPI.RetrieveProjects(context.Background(), uuid).ExcludeInactive(excludeInactive).OnlyRoot(onlyRoot).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `AclAPI.RetrieveProjects``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RetrieveProjects`: []string
	fmt.Fprintf(os.Stdout, "Response from `AclAPI.RetrieveProjects`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the team to retrieve mappings for | 

### Other Parameters

Other parameters are passed through a pointer to a apiRetrieveProjectsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **excludeInactive** | **bool** | Optionally excludes inactive projects from being returned | 
 **onlyRoot** | **bool** | Optionally excludes children projects from being returned | 
 **pageNumber** | [**interface{}**](interface{}.md) | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to 1]
 **pageSize** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to 100]
 **offset** | [**interface{}**](interface{}.md) | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

**[]string**

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

