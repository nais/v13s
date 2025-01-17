# \ProjectAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CloneProject**](ProjectAPI.md#CloneProject) | **Put** /v1/project/clone | Clones a project
[**CreateProject**](ProjectAPI.md#CreateProject) | **Put** /v1/project | Creates a new project
[**DeleteProject**](ProjectAPI.md#DeleteProject) | **Delete** /v1/project/{uuid} | Deletes a project
[**GetChildrenProjects**](ProjectAPI.md#GetChildrenProjects) | **Get** /v1/project/{uuid}/children | Returns a list of all children for a project
[**GetChildrenProjectsByClassifier**](ProjectAPI.md#GetChildrenProjectsByClassifier) | **Get** /v1/project/{uuid}/children/classifier/{classifier} | Returns a list of all children for a project by classifier
[**GetChildrenProjectsByTag**](ProjectAPI.md#GetChildrenProjectsByTag) | **Get** /v1/project/{uuid}/children/tag/{tag} | Returns a list of all children for a project by tag
[**GetProject**](ProjectAPI.md#GetProject) | **Get** /v1/project/{uuid} | Returns a specific project
[**GetProjectByNameAndVersion**](ProjectAPI.md#GetProjectByNameAndVersion) | **Get** /v1/project/lookup | Returns a specific project by its name and version
[**GetProjects**](ProjectAPI.md#GetProjects) | **Get** /v1/project | Returns a list of all projects
[**GetProjectsByClassifier**](ProjectAPI.md#GetProjectsByClassifier) | **Get** /v1/project/classifier/{classifier} | Returns a list of all projects by classifier
[**GetProjectsByTag**](ProjectAPI.md#GetProjectsByTag) | **Get** /v1/project/tag/{tag} | Returns a list of all projects by tag
[**GetProjectsWithoutDescendantsOf**](ProjectAPI.md#GetProjectsWithoutDescendantsOf) | **Get** /v1/project/withoutDescendantsOf/{uuid} | Returns a list of all projects without the descendants of the selected project
[**PatchProject**](ProjectAPI.md#PatchProject) | **Patch** /v1/project/{uuid} | Partially updates a project
[**UpdateProject**](ProjectAPI.md#UpdateProject) | **Post** /v1/project | Updates a project



## CloneProject

> Project CloneProject(ctx).Body(body).Execute()

Clones a project



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
	body := *openapiclient.NewCloneProjectRequest("Project_example") // CloneProjectRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.CloneProject(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.CloneProject``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CloneProject`: Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.CloneProject`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCloneProjectRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**CloneProjectRequest**](CloneProjectRequest.md) |  | 

### Return type

[**Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CreateProject

> Project CreateProject(ctx).Body(body).Execute()

Creates a new project



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
	body := *openapiclient.NewProject("Uuid_example") // Project |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.CreateProject(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.CreateProject``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateProject`: Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.CreateProject`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCreateProjectRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**Project**](Project.md) |  | 

### Return type

[**Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteProject

> DeleteProject(ctx, uuid).Execute()

Deletes a project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to delete

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.ProjectAPI.DeleteProject(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.DeleteProject``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to delete | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteProjectRequest struct via the builder pattern


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


## GetChildrenProjects

> []Project GetChildrenProjects(ctx, uuid).ExcludeInactive(excludeInactive).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all children for a project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to get the children from
	excludeInactive := true // bool | Optionally excludes inactive projects from being returned (optional)
	pageNumber := TODO // interface{} | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to 1)
	pageSize := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to 100)
	offset := TODO // interface{} | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.GetChildrenProjects(context.Background(), uuid).ExcludeInactive(excludeInactive).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.GetChildrenProjects``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetChildrenProjects`: []Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.GetChildrenProjects`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to get the children from | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetChildrenProjectsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **excludeInactive** | **bool** | Optionally excludes inactive projects from being returned | 
 **pageNumber** | [**interface{}**](interface{}.md) | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to 1]
 **pageSize** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to 100]
 **offset** | [**interface{}**](interface{}.md) | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetChildrenProjectsByClassifier

> []Project GetChildrenProjectsByClassifier(ctx, classifier, uuid).ExcludeInactive(excludeInactive).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all children for a project by classifier



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
	classifier := "classifier_example" // string | The classifier to query on
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to get the children from
	excludeInactive := true // bool | Optionally excludes inactive projects from being returned (optional)
	pageNumber := TODO // interface{} | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to 1)
	pageSize := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to 100)
	offset := TODO // interface{} | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.GetChildrenProjectsByClassifier(context.Background(), classifier, uuid).ExcludeInactive(excludeInactive).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.GetChildrenProjectsByClassifier``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetChildrenProjectsByClassifier`: []Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.GetChildrenProjectsByClassifier`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**classifier** | **string** | The classifier to query on | 
**uuid** | **string** | The UUID of the project to get the children from | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetChildrenProjectsByClassifierRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


 **excludeInactive** | **bool** | Optionally excludes inactive projects from being returned | 
 **pageNumber** | [**interface{}**](interface{}.md) | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to 1]
 **pageSize** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to 100]
 **offset** | [**interface{}**](interface{}.md) | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetChildrenProjectsByTag

> []Project GetChildrenProjectsByTag(ctx, tag, uuid).ExcludeInactive(excludeInactive).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all children for a project by tag



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
	tag := "tag_example" // string | The tag to query on
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to get the children from
	excludeInactive := true // bool | Optionally excludes inactive projects from being returned (optional)
	pageNumber := TODO // interface{} | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to 1)
	pageSize := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to 100)
	offset := TODO // interface{} | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.GetChildrenProjectsByTag(context.Background(), tag, uuid).ExcludeInactive(excludeInactive).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.GetChildrenProjectsByTag``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetChildrenProjectsByTag`: []Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.GetChildrenProjectsByTag`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**tag** | **string** | The tag to query on | 
**uuid** | **string** | The UUID of the project to get the children from | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetChildrenProjectsByTagRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


 **excludeInactive** | **bool** | Optionally excludes inactive projects from being returned | 
 **pageNumber** | [**interface{}**](interface{}.md) | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to 1]
 **pageSize** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to 100]
 **offset** | [**interface{}**](interface{}.md) | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProject

> Project GetProject(ctx, uuid).Execute()

Returns a specific project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to retrieve

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.GetProject(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.GetProject``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProject`: Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.GetProject`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to retrieve | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectByNameAndVersion

> Project GetProjectByNameAndVersion(ctx).Name(name).Version(version).Execute()

Returns a specific project by its name and version



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
	resp, r, err := apiClient.ProjectAPI.GetProjectByNameAndVersion(context.Background()).Name(name).Version(version).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.GetProjectByNameAndVersion``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectByNameAndVersion`: Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.GetProjectByNameAndVersion`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectByNameAndVersionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **string** | The name of the project to query on | 
 **version** | **string** | The version of the project to query on | 

### Return type

[**Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjects

> []Project GetProjects(ctx).Name(name).ExcludeInactive(excludeInactive).OnlyRoot(onlyRoot).NotAssignedToTeamWithUuid(notAssignedToTeamWithUuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all projects



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
	name := "name_example" // string | The optional name of the project to query on (optional)
	excludeInactive := true // bool | Optionally excludes inactive projects from being returned (optional)
	onlyRoot := true // bool | Optionally excludes children projects from being returned (optional)
	notAssignedToTeamWithUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the team which projects shall be excluded (optional)
	pageNumber := TODO // interface{} | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to 1)
	pageSize := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to 100)
	offset := TODO // interface{} | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.GetProjects(context.Background()).Name(name).ExcludeInactive(excludeInactive).OnlyRoot(onlyRoot).NotAssignedToTeamWithUuid(notAssignedToTeamWithUuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.GetProjects``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjects`: []Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.GetProjects`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **string** | The optional name of the project to query on | 
 **excludeInactive** | **bool** | Optionally excludes inactive projects from being returned | 
 **onlyRoot** | **bool** | Optionally excludes children projects from being returned | 
 **notAssignedToTeamWithUuid** | **string** | The UUID of the team which projects shall be excluded | 
 **pageNumber** | [**interface{}**](interface{}.md) | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to 1]
 **pageSize** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to 100]
 **offset** | [**interface{}**](interface{}.md) | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectsByClassifier

> []Project GetProjectsByClassifier(ctx, classifier).ExcludeInactive(excludeInactive).OnlyRoot(onlyRoot).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all projects by classifier



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
	classifier := "classifier_example" // string | The classifier to query on
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
	resp, r, err := apiClient.ProjectAPI.GetProjectsByClassifier(context.Background(), classifier).ExcludeInactive(excludeInactive).OnlyRoot(onlyRoot).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.GetProjectsByClassifier``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectsByClassifier`: []Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.GetProjectsByClassifier`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**classifier** | **string** | The classifier to query on | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectsByClassifierRequest struct via the builder pattern


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

[**[]Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectsByTag

> []Project GetProjectsByTag(ctx, tag).ExcludeInactive(excludeInactive).OnlyRoot(onlyRoot).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all projects by tag



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
	tag := "tag_example" // string | The tag to query on
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
	resp, r, err := apiClient.ProjectAPI.GetProjectsByTag(context.Background(), tag).ExcludeInactive(excludeInactive).OnlyRoot(onlyRoot).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.GetProjectsByTag``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectsByTag`: []Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.GetProjectsByTag`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**tag** | **string** | The tag to query on | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectsByTagRequest struct via the builder pattern


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

[**[]Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectsWithoutDescendantsOf

> []Project GetProjectsWithoutDescendantsOf(ctx, uuid).Name(name).ExcludeInactive(excludeInactive).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all projects without the descendants of the selected project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project which descendants will be excluded
	name := "name_example" // string | The optional name of the project to query on (optional)
	excludeInactive := true // bool | Optionally excludes inactive projects from being returned (optional)
	pageNumber := TODO // interface{} | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to 1)
	pageSize := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to 100)
	offset := TODO // interface{} | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.GetProjectsWithoutDescendantsOf(context.Background(), uuid).Name(name).ExcludeInactive(excludeInactive).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.GetProjectsWithoutDescendantsOf``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectsWithoutDescendantsOf`: []Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.GetProjectsWithoutDescendantsOf`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project which descendants will be excluded | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectsWithoutDescendantsOfRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **name** | **string** | The optional name of the project to query on | 
 **excludeInactive** | **bool** | Optionally excludes inactive projects from being returned | 
 **pageNumber** | [**interface{}**](interface{}.md) | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to 1]
 **pageSize** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to 100]
 **offset** | [**interface{}**](interface{}.md) | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## PatchProject

> Project PatchProject(ctx, uuid).Body(body).Execute()

Partially updates a project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to modify
	body := *openapiclient.NewProject("Uuid_example") // Project |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.PatchProject(context.Background(), uuid).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.PatchProject``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `PatchProject`: Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.PatchProject`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to modify | 

### Other Parameters

Other parameters are passed through a pointer to a apiPatchProjectRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **body** | [**Project**](Project.md) |  | 

### Return type

[**Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateProject

> Project UpdateProject(ctx).Body(body).Execute()

Updates a project



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
	body := *openapiclient.NewProject("Uuid_example") // Project |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ProjectAPI.UpdateProject(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ProjectAPI.UpdateProject``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateProject`: Project
	fmt.Fprintf(os.Stdout, "Response from `ProjectAPI.UpdateProject`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateProjectRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**Project**](Project.md) |  | 

### Return type

[**Project**](Project.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)
