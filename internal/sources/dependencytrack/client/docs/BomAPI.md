# \BomAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**ExportComponentAsCycloneDx**](BomAPI.md#ExportComponentAsCycloneDx) | **Get** /v1/bom/cyclonedx/component/{uuid} | Returns dependency metadata for a specific component in CycloneDX format
[**ExportProjectAsCycloneDx**](BomAPI.md#ExportProjectAsCycloneDx) | **Get** /v1/bom/cyclonedx/project/{uuid} | Returns dependency metadata for a project in CycloneDX format
[**IsTokenBeingProcessed**](BomAPI.md#IsTokenBeingProcessed) | **Get** /v1/bom/token/{uuid} | Determines if there are any tasks associated with the token that are being processed, or in the queue to be processed.
[**UploadBom**](BomAPI.md#UploadBom) | **Post** /v1/bom | Upload a supported bill of material format document
[**UploadBomBase64Encoded**](BomAPI.md#UploadBomBase64Encoded) | **Put** /v1/bom | Upload a supported bill of material format document



## ExportComponentAsCycloneDx

> string ExportComponentAsCycloneDx(ctx, uuid).Format(format).Execute()

Returns dependency metadata for a specific component in CycloneDX format



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
	uuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the component to export
	format := "format_example" // string | The format to output (defaults to JSON) (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.BomAPI.ExportComponentAsCycloneDx(context.Background(), uuid).Format(format).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `BomAPI.ExportComponentAsCycloneDx``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ExportComponentAsCycloneDx`: string
	fmt.Fprintf(os.Stdout, "Response from `BomAPI.ExportComponentAsCycloneDx`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the component to export | 

### Other Parameters

Other parameters are passed through a pointer to a apiExportComponentAsCycloneDxRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **format** | **string** | The format to output (defaults to JSON) | 

### Return type

**string**

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/vnd.cyclonedx+xml, application/vnd.cyclonedx+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ExportProjectAsCycloneDx

> string ExportProjectAsCycloneDx(ctx, uuid).Format(format).Variant(variant).Download(download).Execute()

Returns dependency metadata for a project in CycloneDX format



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
	format := "format_example" // string | The format to output (defaults to JSON) (optional)
	variant := "variant_example" // string | Specifies the CycloneDX variant to export. Value options are 'inventory' and 'withVulnerabilities'. (defaults to 'inventory') (optional)
	download := true // bool | Force the resulting BOM to be downloaded as a file (defaults to 'false') (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.BomAPI.ExportProjectAsCycloneDx(context.Background(), uuid).Format(format).Variant(variant).Download(download).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `BomAPI.ExportProjectAsCycloneDx``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ExportProjectAsCycloneDx`: string
	fmt.Fprintf(os.Stdout, "Response from `BomAPI.ExportProjectAsCycloneDx`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the project to export | 

### Other Parameters

Other parameters are passed through a pointer to a apiExportProjectAsCycloneDxRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **format** | **string** | The format to output (defaults to JSON) | 
 **variant** | **string** | Specifies the CycloneDX variant to export. Value options are &#39;inventory&#39; and &#39;withVulnerabilities&#39;. (defaults to &#39;inventory&#39;) | 
 **download** | **bool** | Force the resulting BOM to be downloaded as a file (defaults to &#39;false&#39;) | 

### Return type

**string**

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/vnd.cyclonedx+xml, application/vnd.cyclonedx+json, application/octet-stream

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## IsTokenBeingProcessed

> IsTokenBeingProcessedResponse IsTokenBeingProcessed(ctx, uuid).Execute()

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
	resp, r, err := apiClient.BomAPI.IsTokenBeingProcessed(context.Background(), uuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `BomAPI.IsTokenBeingProcessed``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `IsTokenBeingProcessed`: IsTokenBeingProcessedResponse
	fmt.Fprintf(os.Stdout, "Response from `BomAPI.IsTokenBeingProcessed`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**uuid** | **string** | The UUID of the token to query | 

### Other Parameters

Other parameters are passed through a pointer to a apiIsTokenBeingProcessedRequest struct via the builder pattern


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


## UploadBom

> BomUploadResponse UploadBom(ctx).Project(project).AutoCreate(autoCreate).ProjectName(projectName).ProjectVersion(projectVersion).ProjectTags(projectTags).ParentName(parentName).ParentVersion(parentVersion).ParentUUID(parentUUID).IsLatest(isLatest).Bom(bom).Execute()

Upload a supported bill of material format document



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
	autoCreate := true // bool |  (optional) (default to false)
	projectName := "projectName_example" // string |  (optional)
	projectVersion := "projectVersion_example" // string |  (optional)
	projectTags := "projectTags_example" // string |  (optional)
	parentName := "parentName_example" // string |  (optional)
	parentVersion := "parentVersion_example" // string |  (optional)
	parentUUID := "parentUUID_example" // string |  (optional)
	isLatest := true // bool |  (optional) (default to false)
	bom := "bom_example" // string |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.BomAPI.UploadBom(context.Background()).Project(project).AutoCreate(autoCreate).ProjectName(projectName).ProjectVersion(projectVersion).ProjectTags(projectTags).ParentName(parentName).ParentVersion(parentVersion).ParentUUID(parentUUID).IsLatest(isLatest).Bom(bom).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `BomAPI.UploadBom``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UploadBom`: BomUploadResponse
	fmt.Fprintf(os.Stdout, "Response from `BomAPI.UploadBom`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUploadBomRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **project** | **string** |  | 
 **autoCreate** | **bool** |  | [default to false]
 **projectName** | **string** |  | 
 **projectVersion** | **string** |  | 
 **projectTags** | **string** |  | 
 **parentName** | **string** |  | 
 **parentVersion** | **string** |  | 
 **parentUUID** | **string** |  | 
 **isLatest** | **bool** |  | [default to false]
 **bom** | **string** |  | 

### Return type

[**BomUploadResponse**](BomUploadResponse.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: multipart/form-data
- **Accept**: application/json, application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UploadBomBase64Encoded

> BomUploadResponse UploadBomBase64Encoded(ctx).BomSubmitRequest(bomSubmitRequest).Execute()

Upload a supported bill of material format document



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
	bomSubmitRequest := *openapiclient.NewBomSubmitRequest("38640b33-4ba9-4733-bdab-cbfc40c6f8aa", "ewogICJib21Gb3JtYXQiOiAiQ3ljbG9uZURYIiwKICAic3BlY1ZlcnNpb24iOiAiMS40IiwKICAiY29tcG9uZW50cyI6IFsKICAgIHsKICAgICAgInR5cGUiOiAibGlicmFyeSIsCiAgICAgICJuYW1lIjogImFjbWUtbGliIiwKICAgICAgInZlcnNpb24iOiAiMS4wLjAiCiAgICB9CiAgXQp9") // BomSubmitRequest | 

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.BomAPI.UploadBomBase64Encoded(context.Background()).BomSubmitRequest(bomSubmitRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `BomAPI.UploadBomBase64Encoded``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UploadBomBase64Encoded`: BomUploadResponse
	fmt.Fprintf(os.Stdout, "Response from `BomAPI.UploadBomBase64Encoded`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUploadBomBase64EncodedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **bomSubmitRequest** | [**BomSubmitRequest**](BomSubmitRequest.md) |  | 

### Return type

[**BomUploadResponse**](BomUploadResponse.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json, application/problem+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

