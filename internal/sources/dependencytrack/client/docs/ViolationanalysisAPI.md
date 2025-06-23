# \ViolationanalysisAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**RetrieveAnalysis1**](ViolationanalysisAPI.md#RetrieveAnalysis1) | **Get** /v1/violation/analysis | Retrieves a violation analysis trail
[**UpdateAnalysis1**](ViolationanalysisAPI.md#UpdateAnalysis1) | **Put** /v1/violation/analysis | Records a violation analysis decision



## RetrieveAnalysis1

> ViolationAnalysis RetrieveAnalysis1(ctx).Component(component).PolicyViolation(policyViolation).Execute()

Retrieves a violation analysis trail



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
	component := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component
	policyViolation := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the policy violation

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ViolationanalysisAPI.RetrieveAnalysis1(context.Background()).Component(component).PolicyViolation(policyViolation).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ViolationanalysisAPI.RetrieveAnalysis1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RetrieveAnalysis1`: ViolationAnalysis
	fmt.Fprintf(os.Stdout, "Response from `ViolationanalysisAPI.RetrieveAnalysis1`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiRetrieveAnalysis1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **component** | **string** | The UUID of the component | 
 **policyViolation** | **string** | The UUID of the policy violation | 

### Return type

[**ViolationAnalysis**](ViolationAnalysis.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateAnalysis1

> ViolationAnalysis UpdateAnalysis1(ctx).ViolationAnalysisRequest(violationAnalysisRequest).Execute()

Records a violation analysis decision



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
	violationAnalysisRequest := *openapiclient.NewViolationAnalysisRequest("Component_example", "PolicyViolation_example") // ViolationAnalysisRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.ViolationanalysisAPI.UpdateAnalysis1(context.Background()).ViolationAnalysisRequest(violationAnalysisRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `ViolationanalysisAPI.UpdateAnalysis1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateAnalysis1`: ViolationAnalysis
	fmt.Fprintf(os.Stdout, "Response from `ViolationanalysisAPI.UpdateAnalysis1`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateAnalysis1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **violationAnalysisRequest** | [**ViolationAnalysisRequest**](ViolationAnalysisRequest.md) |  | 

### Return type

[**ViolationAnalysis**](ViolationAnalysis.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

