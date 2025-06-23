# \LicenseGroupAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AddLicenseToLicenseGroup**](LicenseGroupAPI.md#AddLicenseToLicenseGroup) | **Post** /v1/licenseGroup/{uuid}/license/{licenseUuid} | Adds the license to the specified license group.
[**CreateLicenseGroup**](LicenseGroupAPI.md#CreateLicenseGroup) | **Put** /v1/licenseGroup | Creates a new license group
[**DeleteLicenseGroup**](LicenseGroupAPI.md#DeleteLicenseGroup) | **Delete** /v1/licenseGroup/{uuid} | Deletes a license group
[**GetLicenseGroup**](LicenseGroupAPI.md#GetLicenseGroup) | **Get** /v1/licenseGroup/{uuid} | Returns a specific license group
[**GetLicenseGroups**](LicenseGroupAPI.md#GetLicenseGroups) | **Get** /v1/licenseGroup | Returns a list of all license groups
[**RemoveLicenseFromLicenseGroup**](LicenseGroupAPI.md#RemoveLicenseFromLicenseGroup) | **Delete** /v1/licenseGroup/{uuid}/license/{licenseUuid} | Removes the license from the license group.
[**UpdateLicenseGroup**](LicenseGroupAPI.md#UpdateLicenseGroup) | **Post** /v1/licenseGroup | Updates a license group



## AddLicenseToLicenseGroup

> LicenseGroup AddLicenseToLicenseGroup(ctx, uuid, licenseUuid).Execute()

Adds the license to the specified license group.



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | A valid license group
	licenseUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | A valid license

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.LicenseGroupAPI.AddLicenseToLicenseGroup(context.Background(), uuid, licenseUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LicenseGroupAPI.AddLicenseToLicenseGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `AddLicenseToLicenseGroup`: LicenseGroup
	fmt.Fprintf(os.Stdout, "Response from `LicenseGroupAPI.AddLicenseToLicenseGroup`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | A valid license group | 
**licenseUuid** | **string** | A valid license | 

### Other Parameters

Other parameters are passed through a pointer to a apiAddLicenseToLicenseGroupRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**LicenseGroup**](LicenseGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CreateLicenseGroup

> LicenseGroup CreateLicenseGroup(ctx).LicenseGroup(licenseGroup).Execute()

Creates a new license group



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
	licenseGroup := *openapiclient.NewLicenseGroup("Uuid_example") // LicenseGroup |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.LicenseGroupAPI.CreateLicenseGroup(context.Background()).LicenseGroup(licenseGroup).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LicenseGroupAPI.CreateLicenseGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateLicenseGroup`: LicenseGroup
	fmt.Fprintf(os.Stdout, "Response from `LicenseGroupAPI.CreateLicenseGroup`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCreateLicenseGroupRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **licenseGroup** | [**LicenseGroup**](LicenseGroup.md) |  | 

### Return type

[**LicenseGroup**](LicenseGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteLicenseGroup

> DeleteLicenseGroup(ctx, uuid).Execute()

Deletes a license group



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the license group to delete

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.LicenseGroupAPI.DeleteLicenseGroup(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LicenseGroupAPI.DeleteLicenseGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the license group to delete | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteLicenseGroupRequest struct via the builder pattern


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


## GetLicenseGroup

> LicenseGroup GetLicenseGroup(ctx, uuid).Execute()

Returns a specific license group



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the license group to retrieve

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.LicenseGroupAPI.GetLicenseGroup(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LicenseGroupAPI.GetLicenseGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetLicenseGroup`: LicenseGroup
	fmt.Fprintf(os.Stdout, "Response from `LicenseGroupAPI.GetLicenseGroup`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the license group to retrieve | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetLicenseGroupRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**LicenseGroup**](LicenseGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetLicenseGroups

> []LicenseGroup GetLicenseGroups(ctx).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all license groups



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
	resp, r, err := apiClient.LicenseGroupAPI.GetLicenseGroups(context.Background()).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LicenseGroupAPI.GetLicenseGroups``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetLicenseGroups`: []LicenseGroup
	fmt.Fprintf(os.Stdout, "Response from `LicenseGroupAPI.GetLicenseGroups`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetLicenseGroupsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **pageNumber** | **string** | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to &quot;1&quot;]
 **pageSize** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to &quot;100&quot;]
 **offset** | **string** | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | **string** | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]LicenseGroup**](LicenseGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RemoveLicenseFromLicenseGroup

> LicenseGroup RemoveLicenseFromLicenseGroup(ctx, uuid, licenseUuid).Execute()

Removes the license from the license group.



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | A valid license group
	licenseUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | A valid license

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.LicenseGroupAPI.RemoveLicenseFromLicenseGroup(context.Background(), uuid, licenseUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LicenseGroupAPI.RemoveLicenseFromLicenseGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RemoveLicenseFromLicenseGroup`: LicenseGroup
	fmt.Fprintf(os.Stdout, "Response from `LicenseGroupAPI.RemoveLicenseFromLicenseGroup`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | A valid license group | 
**licenseUuid** | **string** | A valid license | 

### Other Parameters

Other parameters are passed through a pointer to a apiRemoveLicenseFromLicenseGroupRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**LicenseGroup**](LicenseGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateLicenseGroup

> LicenseGroup UpdateLicenseGroup(ctx).LicenseGroup(licenseGroup).Execute()

Updates a license group



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
	licenseGroup := *openapiclient.NewLicenseGroup("Uuid_example") // LicenseGroup |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.LicenseGroupAPI.UpdateLicenseGroup(context.Background()).LicenseGroup(licenseGroup).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `LicenseGroupAPI.UpdateLicenseGroup``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateLicenseGroup`: LicenseGroup
	fmt.Fprintf(os.Stdout, "Response from `LicenseGroupAPI.UpdateLicenseGroup`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateLicenseGroupRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **licenseGroup** | [**LicenseGroup**](LicenseGroup.md) |  | 

### Return type

[**LicenseGroup**](LicenseGroup.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

