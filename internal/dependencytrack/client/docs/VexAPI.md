# \VexAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**ExportProjectAsCycloneDx1**](VexAPI.md#ExportProjectAsCycloneDx1) | **Get** /v1/vex/cyclonedx/project/{uuid} | Returns a VEX for a project in CycloneDX format
[**UploadVex**](VexAPI.md#UploadVex) | **Post** /v1/vex | Upload a supported VEX document
[**UploadVex1**](VexAPI.md#UploadVex1) | **Put** /v1/vex | Upload a supported VEX document



## ExportProjectAsCycloneDx1

> string ExportProjectAsCycloneDx1(ctx, uuid).Download(download).Execute()

Returns a VEX for a project in CycloneDX format



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to export
	download := true // bool | Force the resulting VEX to be downloaded as a file (defaults to 'false') (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.VexAPI.ExportProjectAsCycloneDx1(context.Background(), uuid).Download(download).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `VexAPI.ExportProjectAsCycloneDx1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ExportProjectAsCycloneDx1`: string
	fmt.Fprintf(os.Stdout, "Response from `VexAPI.ExportProjectAsCycloneDx1`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to export | 

### Other Parameters

Other parameters are passed through a pointer to a apiExportProjectAsCycloneDx1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **download** | **bool** | Force the resulting VEX to be downloaded as a file (defaults to &#39;false&#39;) | 

### Return type

**string**

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/vnd.cyclonedx+json, application/octet-stream

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UploadVex

> UploadVex(ctx).Project(project).ProjectName(projectName).ProjectVersion(projectVersion).Vex(vex).Execute()

Upload a supported VEX document



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
	project := "project_example" // string |  (optional)
	projectName := "projectName_example" // string |  (optional)
	projectVersion := "projectVersion_example" // string |  (optional)
	vex := "vex_example" // string |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.VexAPI.UploadVex(context.Background()).Project(project).ProjectName(projectName).ProjectVersion(projectVersion).Vex(vex).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `VexAPI.UploadVex``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUploadVexRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **project** | **string** |  | 
 **projectName** | **string** |  | 
 **projectVersion** | **string** |  | 
 **vex** | **string** |  | 

### Return type

 (empty response body)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: multipart/form-data
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UploadVex1

> UploadVex1(ctx).Body(body).Execute()

Upload a supported VEX document



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
	body := *openapiclient.NewVexSubmitRequest("Project_example", "Vex_example") // VexSubmitRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.VexAPI.UploadVex1(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `VexAPI.UploadVex1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUploadVex1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**VexSubmitRequest**](VexSubmitRequest.md) |  | 

### Return type

 (empty response body)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

