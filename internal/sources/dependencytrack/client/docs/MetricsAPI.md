# \MetricsAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetComponentCurrentMetrics**](MetricsAPI.md#GetComponentCurrentMetrics) | **Get** /v1/metrics/component/{uuid}/current | Returns current metrics for a specific component
[**GetComponentMetricsSince**](MetricsAPI.md#GetComponentMetricsSince) | **Get** /v1/metrics/component/{uuid}/since/{date} | Returns historical metrics for a specific component from a specific date
[**GetComponentMetricsXDays**](MetricsAPI.md#GetComponentMetricsXDays) | **Get** /v1/metrics/component/{uuid}/days/{days} | Returns X days of historical metrics for a specific component
[**GetPortfolioCurrentMetrics**](MetricsAPI.md#GetPortfolioCurrentMetrics) | **Get** /v1/metrics/portfolio/current | Returns current metrics for the entire portfolio
[**GetPortfolioMetricsSince**](MetricsAPI.md#GetPortfolioMetricsSince) | **Get** /v1/metrics/portfolio/since/{date} | Returns historical metrics for the entire portfolio from a specific date
[**GetPortfolioMetricsXDays**](MetricsAPI.md#GetPortfolioMetricsXDays) | **Get** /v1/metrics/portfolio/{days}/days | Returns X days of historical metrics for the entire portfolio
[**GetProjectCurrentMetrics**](MetricsAPI.md#GetProjectCurrentMetrics) | **Get** /v1/metrics/project/{uuid}/current | Returns current metrics for a specific project
[**GetProjectMetricsSince**](MetricsAPI.md#GetProjectMetricsSince) | **Get** /v1/metrics/project/{uuid}/since/{date} | Returns historical metrics for a specific project from a specific date
[**GetProjectMetricsXDays**](MetricsAPI.md#GetProjectMetricsXDays) | **Get** /v1/metrics/project/{uuid}/days/{days} | Returns X days of historical metrics for a specific project
[**GetVulnerabilityMetrics**](MetricsAPI.md#GetVulnerabilityMetrics) | **Get** /v1/metrics/vulnerability | Returns the sum of all vulnerabilities in the database by year and month
[**RefreshComponentMetrics**](MetricsAPI.md#RefreshComponentMetrics) | **Get** /v1/metrics/component/{uuid}/refresh | Requests a refresh of a specific components metrics
[**RefreshPortfolioMetrics**](MetricsAPI.md#RefreshPortfolioMetrics) | **Get** /v1/metrics/portfolio/refresh | Requests a refresh of the portfolio metrics
[**RefreshProjectMetrics**](MetricsAPI.md#RefreshProjectMetrics) | **Get** /v1/metrics/project/{uuid}/refresh | Requests a refresh of a specific projects metrics



## GetComponentCurrentMetrics

> DependencyMetrics GetComponentCurrentMetrics(ctx, uuid).Execute()

Returns current metrics for a specific component



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to retrieve metrics for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetComponentCurrentMetrics(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetComponentCurrentMetrics``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComponentCurrentMetrics`: DependencyMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetComponentCurrentMetrics`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to retrieve metrics for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetComponentCurrentMetricsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**DependencyMetrics**](DependencyMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetComponentMetricsSince

> []DependencyMetrics GetComponentMetricsSince(ctx, uuid, date).Execute()

Returns historical metrics for a specific component from a specific date



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to retrieve metrics for
	date := "date_example" // string | The start date to retrieve metrics for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetComponentMetricsSince(context.Background(), uuid, date).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetComponentMetricsSince``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComponentMetricsSince`: []DependencyMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetComponentMetricsSince`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to retrieve metrics for | 
**date** | **string** | The start date to retrieve metrics for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetComponentMetricsSinceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**[]DependencyMetrics**](DependencyMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetComponentMetricsXDays

> []DependencyMetrics GetComponentMetricsXDays(ctx, uuid, days).Execute()

Returns X days of historical metrics for a specific component



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to retrieve metrics for
	days := int32(56) // int32 | The number of days back to retrieve metrics for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetComponentMetricsXDays(context.Background(), uuid, days).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetComponentMetricsXDays``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetComponentMetricsXDays`: []DependencyMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetComponentMetricsXDays`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to retrieve metrics for | 
**days** | **int32** | The number of days back to retrieve metrics for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetComponentMetricsXDaysRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**[]DependencyMetrics**](DependencyMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetPortfolioCurrentMetrics

> PortfolioMetrics GetPortfolioCurrentMetrics(ctx).Execute()

Returns current metrics for the entire portfolio



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

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetPortfolioCurrentMetrics(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetPortfolioCurrentMetrics``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetPortfolioCurrentMetrics`: PortfolioMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetPortfolioCurrentMetrics`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetPortfolioCurrentMetricsRequest struct via the builder pattern


### Return type

[**PortfolioMetrics**](PortfolioMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetPortfolioMetricsSince

> []PortfolioMetrics GetPortfolioMetricsSince(ctx, date).Execute()

Returns historical metrics for the entire portfolio from a specific date



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
	date := "date_example" // string | The start date to retrieve metrics for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetPortfolioMetricsSince(context.Background(), date).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetPortfolioMetricsSince``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetPortfolioMetricsSince`: []PortfolioMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetPortfolioMetricsSince`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**date** | **string** | The start date to retrieve metrics for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetPortfolioMetricsSinceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**[]PortfolioMetrics**](PortfolioMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetPortfolioMetricsXDays

> []PortfolioMetrics GetPortfolioMetricsXDays(ctx, days).Execute()

Returns X days of historical metrics for the entire portfolio



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
	days := int32(56) // int32 | The number of days back to retrieve metrics for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetPortfolioMetricsXDays(context.Background(), days).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetPortfolioMetricsXDays``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetPortfolioMetricsXDays`: []PortfolioMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetPortfolioMetricsXDays`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**days** | **int32** | The number of days back to retrieve metrics for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetPortfolioMetricsXDaysRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**[]PortfolioMetrics**](PortfolioMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectCurrentMetrics

> ProjectMetrics GetProjectCurrentMetrics(ctx, uuid).Execute()

Returns current metrics for a specific project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to retrieve metrics for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetProjectCurrentMetrics(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetProjectCurrentMetrics``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectCurrentMetrics`: ProjectMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetProjectCurrentMetrics`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to retrieve metrics for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectCurrentMetricsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**ProjectMetrics**](ProjectMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectMetricsSince

> []ProjectMetrics GetProjectMetricsSince(ctx, uuid, date).Execute()

Returns historical metrics for a specific project from a specific date



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to retrieve metrics for
	date := "date_example" // string | The start date to retrieve metrics for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetProjectMetricsSince(context.Background(), uuid, date).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetProjectMetricsSince``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectMetricsSince`: []ProjectMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetProjectMetricsSince`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to retrieve metrics for | 
**date** | **string** | The start date to retrieve metrics for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectMetricsSinceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**[]ProjectMetrics**](ProjectMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetProjectMetricsXDays

> []ProjectMetrics GetProjectMetricsXDays(ctx, uuid, days).Execute()

Returns X days of historical metrics for a specific project



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to retrieve metrics for
	days := int32(56) // int32 | The number of days back to retrieve metrics for

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetProjectMetricsXDays(context.Background(), uuid, days).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetProjectMetricsXDays``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetProjectMetricsXDays`: []ProjectMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetProjectMetricsXDays`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to retrieve metrics for | 
**days** | **int32** | The number of days back to retrieve metrics for | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetProjectMetricsXDaysRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**[]ProjectMetrics**](ProjectMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetVulnerabilityMetrics

> []VulnerabilityMetrics GetVulnerabilityMetrics(ctx).Execute()

Returns the sum of all vulnerabilities in the database by year and month



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

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MetricsAPI.GetVulnerabilityMetrics(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.GetVulnerabilityMetrics``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetVulnerabilityMetrics`: []VulnerabilityMetrics
	fmt.Fprintf(os.Stdout, "Response from `MetricsAPI.GetVulnerabilityMetrics`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetVulnerabilityMetricsRequest struct via the builder pattern


### Return type

[**[]VulnerabilityMetrics**](VulnerabilityMetrics.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RefreshComponentMetrics

> RefreshComponentMetrics(ctx, uuid).Execute()

Requests a refresh of a specific components metrics



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to refresh metrics on

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.MetricsAPI.RefreshComponentMetrics(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.RefreshComponentMetrics``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to refresh metrics on | 

### Other Parameters

Other parameters are passed through a pointer to a apiRefreshComponentMetricsRequest struct via the builder pattern


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


## RefreshPortfolioMetrics

> RefreshPortfolioMetrics(ctx).Execute()

Requests a refresh of the portfolio metrics



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

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.MetricsAPI.RefreshPortfolioMetrics(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.RefreshPortfolioMetrics``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiRefreshPortfolioMetricsRequest struct via the builder pattern


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


## RefreshProjectMetrics

> RefreshProjectMetrics(ctx, uuid).Execute()

Requests a refresh of a specific projects metrics



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to refresh metrics on

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.MetricsAPI.RefreshProjectMetrics(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MetricsAPI.RefreshProjectMetrics``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to refresh metrics on | 

### Other Parameters

Other parameters are passed through a pointer to a apiRefreshProjectMetricsRequest struct via the builder pattern


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

