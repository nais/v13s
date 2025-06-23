# \ViolationAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetViolations**](ViolationAPI.md#GetViolations) | **Get** /v1/violation | Returns a list of all policy violations for the entire portfolio
[**GetViolationsByComponent**](ViolationAPI.md#GetViolationsByComponent) | **Get** /v1/violation/component/{uuid} | Returns a list of all policy violations for a specific component
[**GetViolationsByProject**](ViolationAPI.md#GetViolationsByProject) | **Get** /v1/violation/project/{uuid} | Returns a list of all policy violations for a specific project



## GetViolations

> []PolicyViolation GetViolations(ctx).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Suppressed(suppressed).ShowInactive(showInactive).ViolationState(violationState).RiskType(riskType).Policy(policy).AnalysisState(analysisState).OccurredOnDateFrom(occurredOnDateFrom).OccurredOnDateTo(occurredOnDateTo).TextSearchField(textSearchField).TextSearchInput(textSearchInput).Execute()

Returns a list of all policy violations for the entire portfolio



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
	pageNumber := "pageNumber_example" // string | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to "1")
	pageSize := "pageSize_example" // string | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to "100")
	offset := "offset_example" // string | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := "limit_example" // string | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)
	suppressed := true // bool | Optionally includes suppressed violations (optional)
	showInactive := true // bool | Optionally includes inactive projects (optional)
	violationState := "violationState_example" // string | Filter by violation state (optional)
	riskType := "riskType_example" // string | Filter by risk type (optional)
	policy := "policy_example" // string | Filter by policy (optional)
	analysisState := "analysisState_example" // string | Filter by analysis state (optional)
	occurredOnDateFrom := "occurredOnDateFrom_example" // string | Filter occurred on from (optional)
	occurredOnDateTo := "occurredOnDateTo_example" // string | Filter occurred on to (optional)
	textSearchField := "textSearchField_example" // string | Filter the text input in these fields (optional)
	textSearchInput := "textSearchInput_example" // string | Filter by this text input (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ViolationAPI.GetViolations(context.Background()).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Suppressed(suppressed).ShowInactive(showInactive).ViolationState(violationState).RiskType(riskType).Policy(policy).AnalysisState(analysisState).OccurredOnDateFrom(occurredOnDateFrom).OccurredOnDateTo(occurredOnDateTo).TextSearchField(textSearchField).TextSearchInput(textSearchInput).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ViolationAPI.GetViolations``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetViolations`: []PolicyViolation
	fmt.Fprintf(os.Stdout, "Response from `ViolationAPI.GetViolations`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetViolationsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **pageNumber** | **string** | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to &quot;1&quot;]
 **pageSize** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to &quot;100&quot;]
 **offset** | **string** | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 
 **suppressed** | **bool** | Optionally includes suppressed violations | 
 **showInactive** | **bool** | Optionally includes inactive projects | 
 **violationState** | **string** | Filter by violation state | 
 **riskType** | **string** | Filter by risk type | 
 **policy** | **string** | Filter by policy | 
 **analysisState** | **string** | Filter by analysis state | 
 **occurredOnDateFrom** | **string** | Filter occurred on from | 
 **occurredOnDateTo** | **string** | Filter occurred on to | 
 **textSearchField** | **string** | Filter the text input in these fields | 
 **textSearchInput** | **string** | Filter by this text input | 

### Return type

[**[]PolicyViolation**](PolicyViolation.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetViolationsByComponent

> []PolicyViolation GetViolationsByComponent(ctx, uuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Suppressed(suppressed).Execute()

Returns a list of all policy violations for a specific component



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component
	pageNumber := "pageNumber_example" // string | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to "1")
	pageSize := "pageSize_example" // string | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to "100")
	offset := "offset_example" // string | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := "limit_example" // string | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)
	suppressed := true // bool | Optionally includes suppressed violations (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ViolationAPI.GetViolationsByComponent(context.Background(), uuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Suppressed(suppressed).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ViolationAPI.GetViolationsByComponent``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetViolationsByComponent`: []PolicyViolation
	fmt.Fprintf(os.Stdout, "Response from `ViolationAPI.GetViolationsByComponent`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetViolationsByComponentRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **pageNumber** | **string** | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to &quot;1&quot;]
 **pageSize** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to &quot;100&quot;]
 **offset** | **string** | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 
 **suppressed** | **bool** | Optionally includes suppressed violations | 

### Return type

[**[]PolicyViolation**](PolicyViolation.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetViolationsByProject

> []PolicyViolation GetViolationsByProject(ctx, uuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Suppressed(suppressed).Execute()

Returns a list of all policy violations for a specific project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project
	pageNumber := "pageNumber_example" // string | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to "1")
	pageSize := "pageSize_example" // string | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to "100")
	offset := "offset_example" // string | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := "limit_example" // string | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)
	suppressed := true // bool | Optionally includes suppressed violations (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ViolationAPI.GetViolationsByProject(context.Background(), uuid).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Suppressed(suppressed).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ViolationAPI.GetViolationsByProject``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetViolationsByProject`: []PolicyViolation
	fmt.Fprintf(os.Stdout, "Response from `ViolationAPI.GetViolationsByProject`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetViolationsByProjectRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **pageNumber** | **string** | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to &quot;1&quot;]
 **pageSize** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to &quot;100&quot;]
 **offset** | **string** | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 
 **suppressed** | **bool** | Optionally includes suppressed violations | 

### Return type

[**[]PolicyViolation**](PolicyViolation.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

