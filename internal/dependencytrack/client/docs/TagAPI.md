# \TagAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetTags**](TagAPI.md#GetTags) | **Get** /v1/tag/{policyUuid} | Returns a list of all tags associated with a given policy



## GetTags

> []Tag GetTags(ctx, policyUuid).Execute()

Returns a list of all tags associated with a given policy



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
	policyUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the policy

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.TagAPI.GetTags(context.Background(), policyUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `TagAPI.GetTags``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetTags`: []Tag
	fmt.Fprintf(os.Stdout, "Response from `TagAPI.GetTags`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**policyUuid** | **string** | The UUID of the policy | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetTagsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**[]Tag**](Tag.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

