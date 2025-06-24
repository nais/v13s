# \AnalysisAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**RetrieveAnalysis**](AnalysisAPI.md#RetrieveAnalysis) | **Get** /v1/analysis | Retrieves an analysis trail
[**UpdateAnalysis**](AnalysisAPI.md#UpdateAnalysis) | **Put** /v1/analysis | Records an analysis decision



## RetrieveAnalysis

> Analysis RetrieveAnalysis(ctx).Component(component).Vulnerability(vulnerability).Project(project).Execute()

Retrieves an analysis trail



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
	vulnerability := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the vulnerability
	project := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.AnalysisAPI.RetrieveAnalysis(context.Background()).Component(component).Vulnerability(vulnerability).Project(project).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `AnalysisAPI.RetrieveAnalysis``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RetrieveAnalysis`: Analysis
	fmt.Fprintf(os.Stdout, "Response from `AnalysisAPI.RetrieveAnalysis`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiRetrieveAnalysisRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **component** | **string** | The UUID of the component | 
 **vulnerability** | **string** | The UUID of the vulnerability | 
 **project** | **string** | The UUID of the project | 

### Return type

[**Analysis**](Analysis.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateAnalysis

> Analysis UpdateAnalysis(ctx).AnalysisRequest(analysisRequest).Execute()

Records an analysis decision



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
	analysisRequest := *openapiclient.NewAnalysisRequest("Component_example", "Vulnerability_example") // AnalysisRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.AnalysisAPI.UpdateAnalysis(context.Background()).AnalysisRequest(analysisRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `AnalysisAPI.UpdateAnalysis``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateAnalysis`: Analysis
	fmt.Fprintf(os.Stdout, "Response from `AnalysisAPI.UpdateAnalysis`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateAnalysisRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **analysisRequest** | [**AnalysisRequest**](AnalysisRequest.md) |  | 

### Return type

[**Analysis**](Analysis.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

