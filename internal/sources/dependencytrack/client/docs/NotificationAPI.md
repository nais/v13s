# \NotificationAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AddProjectToRule**](NotificationAPI.md#AddProjectToRule) | **Post** /v1/notification/rule/{ruleUuid}/project/{projectUuid} | Adds a project to a notification rule
[**AddTeamToRule**](NotificationAPI.md#AddTeamToRule) | **Post** /v1/notification/rule/{ruleUuid}/team/{teamUuid} | Adds a team to a notification rule
[**CreateNotificationPublisher**](NotificationAPI.md#CreateNotificationPublisher) | **Put** /v1/notification/publisher | Creates a new notification publisher
[**CreateNotificationRule**](NotificationAPI.md#CreateNotificationRule) | **Put** /v1/notification/rule | Creates a new notification rule
[**DeleteNotificationPublisher**](NotificationAPI.md#DeleteNotificationPublisher) | **Delete** /v1/notification/publisher/{notificationPublisherUuid} | Deletes a notification publisher and all related notification rules
[**DeleteNotificationRule**](NotificationAPI.md#DeleteNotificationRule) | **Delete** /v1/notification/rule | Deletes a notification rule
[**GetAllNotificationPublishers**](NotificationAPI.md#GetAllNotificationPublishers) | **Get** /v1/notification/publisher | Returns a list of all notification publishers
[**GetAllNotificationRules**](NotificationAPI.md#GetAllNotificationRules) | **Get** /v1/notification/rule | Returns a list of all notification rules
[**RemoveProjectFromRule**](NotificationAPI.md#RemoveProjectFromRule) | **Delete** /v1/notification/rule/{ruleUuid}/project/{projectUuid} | Removes a project from a notification rule
[**RemoveTeamFromRule**](NotificationAPI.md#RemoveTeamFromRule) | **Delete** /v1/notification/rule/{ruleUuid}/team/{teamUuid} | Removes a team from a notification rule
[**RestoreDefaultTemplates**](NotificationAPI.md#RestoreDefaultTemplates) | **Post** /v1/notification/publisher/restoreDefaultTemplates | Restore the default notification publisher templates using the ones in the solution classpath
[**TestSmtpPublisherConfig**](NotificationAPI.md#TestSmtpPublisherConfig) | **Post** /v1/notification/publisher/test/smtp | Dispatches a SMTP notification test
[**UpdateNotificationPublisher**](NotificationAPI.md#UpdateNotificationPublisher) | **Post** /v1/notification/publisher | Updates a notification publisher
[**UpdateNotificationRule**](NotificationAPI.md#UpdateNotificationRule) | **Post** /v1/notification/rule | Updates a notification rule



## AddProjectToRule

> NotificationRule AddProjectToRule(ctx, ruleUuid, projectUuid).Execute()

Adds a project to a notification rule



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
	ruleUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the rule to add a project to
	projectUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to add to the rule

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.NotificationAPI.AddProjectToRule(context.Background(), ruleUuid, projectUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.AddProjectToRule``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `AddProjectToRule`: NotificationRule
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.AddProjectToRule`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**ruleUuid** | **string** | The UUID of the rule to add a project to | 
**projectUuid** | **string** | The UUID of the project to add to the rule | 

### Other Parameters

Other parameters are passed through a pointer to a apiAddProjectToRuleRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**NotificationRule**](NotificationRule.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AddTeamToRule

> NotificationRule AddTeamToRule(ctx, ruleUuid, teamUuid).Execute()

Adds a team to a notification rule



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
	ruleUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the rule to add a team to
	teamUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the team to add to the rule

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.NotificationAPI.AddTeamToRule(context.Background(), ruleUuid, teamUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.AddTeamToRule``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `AddTeamToRule`: NotificationRule
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.AddTeamToRule`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**ruleUuid** | **string** | The UUID of the rule to add a team to | 
**teamUuid** | **string** | The UUID of the team to add to the rule | 

### Other Parameters

Other parameters are passed through a pointer to a apiAddTeamToRuleRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**NotificationRule**](NotificationRule.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CreateNotificationPublisher

> NotificationPublisher CreateNotificationPublisher(ctx).Body(body).Execute()

Creates a new notification publisher



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
	body := *openapiclient.NewNotificationPublisher("Name_example", "PublisherClass_example", "TemplateMimeType_example", "Uuid_example") // NotificationPublisher |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.NotificationAPI.CreateNotificationPublisher(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.CreateNotificationPublisher``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateNotificationPublisher`: NotificationPublisher
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.CreateNotificationPublisher`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCreateNotificationPublisherRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**NotificationPublisher**](NotificationPublisher.md) |  | 

### Return type

[**NotificationPublisher**](NotificationPublisher.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CreateNotificationRule

> NotificationRule CreateNotificationRule(ctx).Body(body).Execute()

Creates a new notification rule



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
	body := *openapiclient.NewNotificationRule("Name_example", "Scope_example", "Uuid_example") // NotificationRule |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.NotificationAPI.CreateNotificationRule(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.CreateNotificationRule``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateNotificationRule`: NotificationRule
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.CreateNotificationRule`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCreateNotificationRuleRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**NotificationRule**](NotificationRule.md) |  | 

### Return type

[**NotificationRule**](NotificationRule.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteNotificationPublisher

> DeleteNotificationPublisher(ctx, notificationPublisherUuid).Execute()

Deletes a notification publisher and all related notification rules



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
	notificationPublisherUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the notification publisher to delete

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.NotificationAPI.DeleteNotificationPublisher(context.Background(), notificationPublisherUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.DeleteNotificationPublisher``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**notificationPublisherUuid** | **string** | The UUID of the notification publisher to delete | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteNotificationPublisherRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

 (empty response body)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteNotificationRule

> DeleteNotificationRule(ctx).Body(body).Execute()

Deletes a notification rule



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
	body := *openapiclient.NewNotificationRule("Name_example", "Scope_example", "Uuid_example") // NotificationRule |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.NotificationAPI.DeleteNotificationRule(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.DeleteNotificationRule``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiDeleteNotificationRuleRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**NotificationRule**](NotificationRule.md) |  | 

### Return type

 (empty response body)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetAllNotificationPublishers

> []NotificationPublisher GetAllNotificationPublishers(ctx).Execute()

Returns a list of all notification publishers



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
	resp, r, err := apiClient.NotificationAPI.GetAllNotificationPublishers(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.GetAllNotificationPublishers``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetAllNotificationPublishers`: []NotificationPublisher
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.GetAllNotificationPublishers`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetAllNotificationPublishersRequest struct via the builder pattern


### Return type

[**[]NotificationPublisher**](NotificationPublisher.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetAllNotificationRules

> []NotificationRule GetAllNotificationRules(ctx).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()

Returns a list of all notification rules



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
	pageNumber := TODO // interface{} | The page to return. To be used in conjunction with <code>pageSize</code>. (optional) (default to 1)
	pageSize := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>pageNumber</code>. (optional) (default to 100)
	offset := TODO // interface{} | Offset to start returning elements from. To be used in conjunction with <code>limit</code>. (optional)
	limit := TODO // interface{} | Number of elements to return per page. To be used in conjunction with <code>offset</code>. (optional)
	sortName := "sortName_example" // string | Name of the resource field to sort on. (optional)
	sortOrder := "sortOrder_example" // string | Ordering of items when sorting with <code>sortName</code>. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.NotificationAPI.GetAllNotificationRules(context.Background()).PageNumber(pageNumber).PageSize(pageSize).Offset(offset).Limit(limit).SortName(sortName).SortOrder(sortOrder).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.GetAllNotificationRules``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetAllNotificationRules`: []NotificationRule
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.GetAllNotificationRules`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetAllNotificationRulesRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **pageNumber** | [**interface{}**](interface{}.md) | The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;. | [default to 1]
 **pageSize** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;. | [default to 100]
 **offset** | [**interface{}**](interface{}.md) | Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;. | 
 **limit** | [**interface{}**](interface{}.md) | Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;. | 
 **sortName** | **string** | Name of the resource field to sort on. | 
 **sortOrder** | **string** | Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;. | 

### Return type

[**[]NotificationRule**](NotificationRule.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RemoveProjectFromRule

> NotificationRule RemoveProjectFromRule(ctx, ruleUuid, projectUuid).Execute()

Removes a project from a notification rule



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
	ruleUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the rule to remove the project from
	projectUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to remove from the rule

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.NotificationAPI.RemoveProjectFromRule(context.Background(), ruleUuid, projectUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.RemoveProjectFromRule``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RemoveProjectFromRule`: NotificationRule
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.RemoveProjectFromRule`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**ruleUuid** | **string** | The UUID of the rule to remove the project from | 
**projectUuid** | **string** | The UUID of the project to remove from the rule | 

### Other Parameters

Other parameters are passed through a pointer to a apiRemoveProjectFromRuleRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**NotificationRule**](NotificationRule.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RemoveTeamFromRule

> NotificationRule RemoveTeamFromRule(ctx, ruleUuid, teamUuid).Execute()

Removes a team from a notification rule



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
	ruleUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the rule to remove the project from
	teamUuid := "38400000-8cf0-11bd-b23e-10b96e4ef00d" // string | The UUID of the project to remove from the rule

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.NotificationAPI.RemoveTeamFromRule(context.Background(), ruleUuid, teamUuid).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.RemoveTeamFromRule``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RemoveTeamFromRule`: NotificationRule
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.RemoveTeamFromRule`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**ruleUuid** | **string** | The UUID of the rule to remove the project from | 
**teamUuid** | **string** | The UUID of the project to remove from the rule | 

### Other Parameters

Other parameters are passed through a pointer to a apiRemoveTeamFromRuleRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



### Return type

[**NotificationRule**](NotificationRule.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RestoreDefaultTemplates

> RestoreDefaultTemplates(ctx).Execute()

Restore the default notification publisher templates using the ones in the solution classpath



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
	r, err := apiClient.NotificationAPI.RestoreDefaultTemplates(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.RestoreDefaultTemplates``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiRestoreDefaultTemplatesRequest struct via the builder pattern


### Return type

 (empty response body)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## TestSmtpPublisherConfig

> TestSmtpPublisherConfig(ctx).Destination(destination).Execute()

Dispatches a SMTP notification test



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
	destination := "destination_example" // string |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.NotificationAPI.TestSmtpPublisherConfig(context.Background()).Destination(destination).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.TestSmtpPublisherConfig``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiTestSmtpPublisherConfigRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **destination** | **string** |  | 

### Return type

 (empty response body)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/x-www-form-urlencoded
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateNotificationPublisher

> NotificationRule UpdateNotificationPublisher(ctx).Body(body).Execute()

Updates a notification publisher



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
	body := *openapiclient.NewNotificationPublisher("Name_example", "PublisherClass_example", "TemplateMimeType_example", "Uuid_example") // NotificationPublisher |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.NotificationAPI.UpdateNotificationPublisher(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.UpdateNotificationPublisher``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateNotificationPublisher`: NotificationRule
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.UpdateNotificationPublisher`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateNotificationPublisherRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**NotificationPublisher**](NotificationPublisher.md) |  | 

### Return type

[**NotificationRule**](NotificationRule.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateNotificationRule

> NotificationRule UpdateNotificationRule(ctx).Body(body).Execute()

Updates a notification rule



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
	body := *openapiclient.NewNotificationRule("Name_example", "Scope_example", "Uuid_example") // NotificationRule |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.NotificationAPI.UpdateNotificationRule(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `NotificationAPI.UpdateNotificationRule``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateNotificationRule`: NotificationRule
	fmt.Fprintf(os.Stdout, "Response from `NotificationAPI.UpdateNotificationRule`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateNotificationRuleRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**NotificationRule**](NotificationRule.md) |  | 

### Return type

[**NotificationRule**](NotificationRule.md)

### Authorization

[X-Api-Key](../README.md#X-Api-Key)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

