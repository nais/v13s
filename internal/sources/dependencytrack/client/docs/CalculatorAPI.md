# \CalculatorAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetCvssScores**](CalculatorAPI.md#GetCvssScores) | **Get** /v1/calculator/cvss | Returns the CVSS base score, impact sub-score and exploitability sub-score
[**GetOwaspRRScores**](CalculatorAPI.md#GetOwaspRRScores) | **Get** /v1/calculator/owasp | Returns the OWASP Risk Rating likelihood score, technical impact score and business impact score



## GetCvssScores

> Score GetCvssScores(ctx).Vector(vector).Execute()

Returns the CVSS base score, impact sub-score and exploitability sub-score

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
	vector := "vector_example" // string | A valid CVSSv2 or CVSSv3 vector

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.CalculatorAPI.GetCvssScores(context.Background()).Vector(vector).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `CalculatorAPI.GetCvssScores``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetCvssScores`: Score
	fmt.Fprintf(os.Stdout, "Response from `CalculatorAPI.GetCvssScores`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetCvssScoresRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vector** | **string** | A valid CVSSv2 or CVSSv3 vector | 

### Return type

[**Score**](Score.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetOwaspRRScores

> Score GetOwaspRRScores(ctx).Vector(vector).Execute()

Returns the OWASP Risk Rating likelihood score, technical impact score and business impact score

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
	vector := "vector_example" // string | A valid OWASP Risk Rating vector

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.CalculatorAPI.GetOwaspRRScores(context.Background()).Vector(vector).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `CalculatorAPI.GetOwaspRRScores``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetOwaspRRScores`: Score
	fmt.Fprintf(os.Stdout, "Response from `CalculatorAPI.GetOwaspRRScores`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetOwaspRRScoresRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vector** | **string** | A valid OWASP Risk Rating vector | 

### Return type

[**Score**](Score.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

