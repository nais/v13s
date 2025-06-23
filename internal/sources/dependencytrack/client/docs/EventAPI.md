# \EventAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**IsTokenBeingProcessed1**](EventAPI.md#IsTokenBeingProcessed1) | **Get** /v1/event/token/{uuid} | Determines if there are any tasks associated with the token that are being processed, or in the queue to be processed.



## IsTokenBeingProcessed1

> IsTokenBeingProcessedResponse IsTokenBeingProcessed1(ctx, uuid).Execute()

Determines if there are any tasks associated with the token that are being processed, or in the queue to be processed.



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the token to query

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.EventAPI.IsTokenBeingProcessed1(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `EventAPI.IsTokenBeingProcessed1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `IsTokenBeingProcessed1`: IsTokenBeingProcessedResponse
	fmt.Fprintf(os.Stdout, "Response from `EventAPI.IsTokenBeingProcessed1`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the token to query | 

### Other Parameters

Other parameters are passed through a pointer to a apiIsTokenBeingProcessed1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**IsTokenBeingProcessedResponse**](IsTokenBeingProcessedResponse.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

