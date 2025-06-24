# \UserAPI

All URIs are relative to */api*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AddTeamToUser**](UserAPI.md#AddTeamToUser) | **Post** /v1/user/{username}/membership | Adds the username to the specified team.
[**CreateLdapUser**](UserAPI.md#CreateLdapUser) | **Put** /v1/user/ldap | Creates a new user that references an existing LDAP object.
[**CreateManagedUser**](UserAPI.md#CreateManagedUser) | **Put** /v1/user/managed | Creates a new user.
[**CreateOidcUser**](UserAPI.md#CreateOidcUser) | **Put** /v1/user/oidc | Creates a new user that references an existing OpenID Connect user.
[**DeleteLdapUser**](UserAPI.md#DeleteLdapUser) | **Delete** /v1/user/ldap | Deletes a user.
[**DeleteManagedUser**](UserAPI.md#DeleteManagedUser) | **Delete** /v1/user/managed | Deletes a user.
[**DeleteOidcUser**](UserAPI.md#DeleteOidcUser) | **Delete** /v1/user/oidc | Deletes an OpenID Connect user.
[**ForceChangePassword**](UserAPI.md#ForceChangePassword) | **Post** /v1/user/forceChangePassword | Asserts login credentials and upon successful authentication, verifies passwords match and changes users password
[**GetLdapUsers**](UserAPI.md#GetLdapUsers) | **Get** /v1/user/ldap | Returns a list of all LDAP users
[**GetManagedUsers**](UserAPI.md#GetManagedUsers) | **Get** /v1/user/managed | Returns a list of all managed users
[**GetOidcUsers**](UserAPI.md#GetOidcUsers) | **Get** /v1/user/oidc | Returns a list of all OIDC users
[**GetSelf1**](UserAPI.md#GetSelf1) | **Get** /v1/user/self | Returns information about the current logged in user.
[**RemoveTeamFromUser**](UserAPI.md#RemoveTeamFromUser) | **Delete** /v1/user/{username}/membership | Removes the username from the specified team.
[**UpdateManagedUser**](UserAPI.md#UpdateManagedUser) | **Post** /v1/user/managed | Updates a managed user.
[**UpdateSelf**](UserAPI.md#UpdateSelf) | **Post** /v1/user/self | Updates information about the current logged in user.
[**ValidateCredentials**](UserAPI.md#ValidateCredentials) | **Post** /v1/user/login | Assert login credentials
[**ValidateOidcAccessToken**](UserAPI.md#ValidateOidcAccessToken) | **Post** /v1/user/oidc/login | Login with OpenID Connect



## AddTeamToUser

> UserPrincipal AddTeamToUser(ctx, username).IdentifiableObject(identifiableObject).Execute()

Adds the username to the specified team.



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
	username := "username_example" // string | A valid username
	identifiableObject := *openapiclient.NewIdentifiableObject() // IdentifiableObject | The UUID of the team to associate username with

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.UserAPI.AddTeamToUser(context.Background(), username).IdentifiableObject(identifiableObject).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.AddTeamToUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `AddTeamToUser`: UserPrincipal
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.AddTeamToUser`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string** | A valid username | 

### Other Parameters

Other parameters are passed through a pointer to a apiAddTeamToUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **identifiableObject** | [**IdentifiableObject**](IdentifiableObject.md) | The UUID of the team to associate username with | 

### Return type

[**UserPrincipal**](UserPrincipal.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CreateLdapUser

> LdapUser CreateLdapUser(ctx).LdapUser(ldapUser).Execute()

Creates a new user that references an existing LDAP object.



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
	ldapUser := *openapiclient.NewLdapUser() // LdapUser |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.UserAPI.CreateLdapUser(context.Background()).LdapUser(ldapUser).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.CreateLdapUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateLdapUser`: LdapUser
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.CreateLdapUser`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCreateLdapUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ldapUser** | [**LdapUser**](LdapUser.md) |  | 

### Return type

[**LdapUser**](LdapUser.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CreateManagedUser

> ManagedUser CreateManagedUser(ctx).ManagedUser(managedUser).Execute()

Creates a new user.



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
	managedUser := *openapiclient.NewManagedUser(int64(123)) // ManagedUser |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.UserAPI.CreateManagedUser(context.Background()).ManagedUser(managedUser).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.CreateManagedUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateManagedUser`: ManagedUser
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.CreateManagedUser`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCreateManagedUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **managedUser** | [**ManagedUser**](ManagedUser.md) |  | 

### Return type

[**ManagedUser**](ManagedUser.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CreateOidcUser

> OidcUser CreateOidcUser(ctx).OidcUser(oidcUser).Execute()

Creates a new user that references an existing OpenID Connect user.



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
	oidcUser := *openapiclient.NewOidcUser() // OidcUser |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.UserAPI.CreateOidcUser(context.Background()).OidcUser(oidcUser).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.CreateOidcUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateOidcUser`: OidcUser
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.CreateOidcUser`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCreateOidcUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **oidcUser** | [**OidcUser**](OidcUser.md) |  | 

### Return type

[**OidcUser**](OidcUser.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteLdapUser

> DeleteLdapUser(ctx).LdapUser(ldapUser).Execute()

Deletes a user.



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
	ldapUser := *openapiclient.NewLdapUser() // LdapUser |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.UserAPI.DeleteLdapUser(context.Background()).LdapUser(ldapUser).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.DeleteLdapUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiDeleteLdapUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ldapUser** | [**LdapUser**](LdapUser.md) |  | 

### Return type

 (empty response body)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteManagedUser

> DeleteManagedUser(ctx).ManagedUser(managedUser).Execute()

Deletes a user.



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
	managedUser := *openapiclient.NewManagedUser(int64(123)) // ManagedUser |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.UserAPI.DeleteManagedUser(context.Background()).ManagedUser(managedUser).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.DeleteManagedUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiDeleteManagedUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **managedUser** | [**ManagedUser**](ManagedUser.md) |  | 

### Return type

 (empty response body)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteOidcUser

> DeleteOidcUser(ctx).OidcUser(oidcUser).Execute()

Deletes an OpenID Connect user.



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
	oidcUser := *openapiclient.NewOidcUser() // OidcUser |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.UserAPI.DeleteOidcUser(context.Background()).OidcUser(oidcUser).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.DeleteOidcUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiDeleteOidcUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **oidcUser** | [**OidcUser**](OidcUser.md) |  | 

### Return type

 (empty response body)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ForceChangePassword

> ForceChangePassword(ctx).Username(username).Password(password).NewPassword(newPassword).ConfirmPassword(confirmPassword).Execute()

Asserts login credentials and upon successful authentication, verifies passwords match and changes users password



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
	username := "username_example" // string |  (optional)
	password := "password_example" // string |  (optional)
	newPassword := "newPassword_example" // string |  (optional)
	confirmPassword := "confirmPassword_example" // string |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	r, err := apiClient.UserAPI.ForceChangePassword(context.Background()).Username(username).Password(password).NewPassword(newPassword).ConfirmPassword(confirmPassword).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.ForceChangePassword``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiForceChangePasswordRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **username** | **string** |  | 
 **password** | **string** |  | 
 **newPassword** | **string** |  | 
 **confirmPassword** | **string** |  | 

### Return type

 (empty response body)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/x-www-form-urlencoded
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetLdapUsers

> []LdapUser GetLdapUsers(ctx).Execute()

Returns a list of all LDAP users



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
	resp, r, err := apiClient.UserAPI.GetLdapUsers(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.GetLdapUsers``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetLdapUsers`: []LdapUser
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.GetLdapUsers`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetLdapUsersRequest struct via the builder pattern


### Return type

[**[]LdapUser**](LdapUser.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetManagedUsers

> []ManagedUser GetManagedUsers(ctx).Execute()

Returns a list of all managed users



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
	resp, r, err := apiClient.UserAPI.GetManagedUsers(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.GetManagedUsers``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetManagedUsers`: []ManagedUser
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.GetManagedUsers`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetManagedUsersRequest struct via the builder pattern


### Return type

[**[]ManagedUser**](ManagedUser.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetOidcUsers

> []OidcUser GetOidcUsers(ctx).Execute()

Returns a list of all OIDC users



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
	resp, r, err := apiClient.UserAPI.GetOidcUsers(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.GetOidcUsers``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetOidcUsers`: []OidcUser
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.GetOidcUsers`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetOidcUsersRequest struct via the builder pattern


### Return type

[**[]OidcUser**](OidcUser.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetSelf1

> UserPrincipal GetSelf1(ctx).Execute()

Returns information about the current logged in user.

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
	resp, r, err := apiClient.UserAPI.GetSelf1(context.Background()).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.GetSelf1``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetSelf1`: UserPrincipal
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.GetSelf1`: %v\n", resp)
}
```

### Path Parameters

This endpoint does not need any parameter.

### Other Parameters

Other parameters are passed through a pointer to a apiGetSelf1Request struct via the builder pattern


### Return type

[**UserPrincipal**](UserPrincipal.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RemoveTeamFromUser

> UserPrincipal RemoveTeamFromUser(ctx, username).IdentifiableObject(identifiableObject).Execute()

Removes the username from the specified team.



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
	username := "username_example" // string | A valid username
	identifiableObject := *openapiclient.NewIdentifiableObject() // IdentifiableObject | The UUID of the team to un-associate username from

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.UserAPI.RemoveTeamFromUser(context.Background(), username).IdentifiableObject(identifiableObject).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.RemoveTeamFromUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `RemoveTeamFromUser`: UserPrincipal
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.RemoveTeamFromUser`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**username** | **string** | A valid username | 

### Other Parameters

Other parameters are passed through a pointer to a apiRemoveTeamFromUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **identifiableObject** | [**IdentifiableObject**](IdentifiableObject.md) | The UUID of the team to un-associate username from | 

### Return type

[**UserPrincipal**](UserPrincipal.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateManagedUser

> ManagedUser UpdateManagedUser(ctx).ManagedUser(managedUser).Execute()

Updates a managed user.



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
	managedUser := *openapiclient.NewManagedUser(int64(123)) // ManagedUser |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.UserAPI.UpdateManagedUser(context.Background()).ManagedUser(managedUser).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.UpdateManagedUser``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateManagedUser`: ManagedUser
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.UpdateManagedUser`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateManagedUserRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **managedUser** | [**ManagedUser**](ManagedUser.md) |  | 

### Return type

[**ManagedUser**](ManagedUser.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## UpdateSelf

> ManagedUser UpdateSelf(ctx).ManagedUser(managedUser).Execute()

Updates information about the current logged in user.

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
	managedUser := *openapiclient.NewManagedUser(int64(123)) // ManagedUser |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.UserAPI.UpdateSelf(context.Background()).ManagedUser(managedUser).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.UpdateSelf``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `UpdateSelf`: ManagedUser
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.UpdateSelf`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiUpdateSelfRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **managedUser** | [**ManagedUser**](ManagedUser.md) |  | 

### Return type

[**ManagedUser**](ManagedUser.md)

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ValidateCredentials

> string ValidateCredentials(ctx).Username(username).Password(password).Execute()

Assert login credentials



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
	username := "username_example" // string |  (optional)
	password := "password_example" // string |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.UserAPI.ValidateCredentials(context.Background()).Username(username).Password(password).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.ValidateCredentials``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ValidateCredentials`: string
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.ValidateCredentials`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiValidateCredentialsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **username** | **string** |  | 
 **password** | **string** |  | 

### Return type

**string**

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/x-www-form-urlencoded
- **Accept**: text/plain

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ValidateOidcAccessToken

> string ValidateOidcAccessToken(ctx).IdToken(idToken).AccessToken(accessToken).Execute()

Login with OpenID Connect



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
	idToken := "idToken_example" // string | An OAuth2 access token
	accessToken := "accessToken_example" // string |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.UserAPI.ValidateOidcAccessToken(context.Background()).IdToken(idToken).AccessToken(accessToken).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `UserAPI.ValidateOidcAccessToken``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `ValidateOidcAccessToken`: string
	fmt.Fprintf(os.Stdout, "Response from `UserAPI.ValidateOidcAccessToken`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiValidateOidcAccessTokenRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **idToken** | **string** | An OAuth2 access token | 
 **accessToken** | **string** |  | 

### Return type

**string**

### Authorization

[ApiKeyAuth](../README.md#ApiKeyAuth), [BearerAuth](../README.md#BearerAuth)

### HTTP request headers

- **Content-Type**: application/x-www-form-urlencoded
- **Accept**: text/plain

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

