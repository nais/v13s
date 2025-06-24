# \CweAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetCwe**](CweAPI.md#GetCwe) | **Get** /v1/cwe/{cweId} | Returns a specific CWE
[**GetCwes**](CweAPI.md#GetCwes) | **Get** /v1/cwe | Returns a list of all CWEs



## GetCwe

> Cwe GetCwe(ctx, cweId).Execute()

Returns a specific CWE

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
	cweId := int32(56) // int32 | The CWE ID of the CWE to retrieve

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.CweAPI.GetCwe(context.Background(), cweId).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `CweAPI.GetCwe``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetCwe`: Cwe
	fmt.Fprintf(os.Stdout, "Response from `CweAPI.GetCwe`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**cweId** | **int32** | The CWE ID of the CWE to retrieve | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetCweRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**Cwe**](Cwe.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetCwes

> []Cwe GetCwes(ctx).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all CWEs

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

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.CweAPI.GetCwes(context.Background()).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `CweAPI.GetCwes``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetCwes`: []Cwe
	fmt.Fprintf(os.Stdout, "Response from `CweAPI.GetCwes`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetCwesRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **pageNumber** | **string** | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to &quot;1&quot;]
 **pageSize** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to &quot;100&quot;]
 **offset** | **string** | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]Cwe**](Cwe.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

