# UserPrincipal

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**Permissions** | Pointer to [**[]Permission**](Permission.md) |  | [optional] 
**Id** | Pointer to **int64** |  | [optional] 
**Username** | Pointer to **string** |  | [optional] 
**Teams** | Pointer to [**[]Team**](Team.md) |  | [optional] 
**Email** | Pointer to **string** |  | [optional] 

## Methods

### NewUserPrincipal

`func NewUserPrincipal() *UserPrincipal`

NewUserPrincipal instantiates a new UserPrincipal object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewUserPrincipalWithDefaults

`func NewUserPrincipalWithDefaults() *UserPrincipal`

NewUserPrincipalWithDefaults instantiates a new UserPrincipal object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *UserPrincipal) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *UserPrincipal) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *UserPrincipal) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *UserPrincipal) HasName() bool`

HasName returns a boolean if a field has been set.

### GetPermissions

`func (o *UserPrincipal) GetPermissions() []Permission`

GetPermissions returns the Permissions field if non-nil, zero value otherwise.

### GetPermissionsOk

`func (o *UserPrincipal) GetPermissionsOk() (*[]Permission, bool)`

GetPermissionsOk returns a tuple with the Permissions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPermissions

`func (o *UserPrincipal) SetPermissions(v []Permission)`

SetPermissions sets Permissions field to given value.

### HasPermissions

`func (o *UserPrincipal) HasPermissions() bool`

HasPermissions returns a boolean if a field has been set.

### GetId

`func (o *UserPrincipal) GetId() int64`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *UserPrincipal) GetIdOk() (*int64, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *UserPrincipal) SetId(v int64)`

SetId sets Id field to given value.

### HasId

`func (o *UserPrincipal) HasId() bool`

HasId returns a boolean if a field has been set.

### GetUsername

`func (o *UserPrincipal) GetUsername() string`

GetUsername returns the Username field if non-nil, zero value otherwise.

### GetUsernameOk

`func (o *UserPrincipal) GetUsernameOk() (*string, bool)`

GetUsernameOk returns a tuple with the Username field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUsername

`func (o *UserPrincipal) SetUsername(v string)`

SetUsername sets Username field to given value.

### HasUsername

`func (o *UserPrincipal) HasUsername() bool`

HasUsername returns a boolean if a field has been set.

### GetTeams

`func (o *UserPrincipal) GetTeams() []Team`

GetTeams returns the Teams field if non-nil, zero value otherwise.

### GetTeamsOk

`func (o *UserPrincipal) GetTeamsOk() (*[]Team, bool)`

GetTeamsOk returns a tuple with the Teams field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTeams

`func (o *UserPrincipal) SetTeams(v []Team)`

SetTeams sets Teams field to given value.

### HasTeams

`func (o *UserPrincipal) HasTeams() bool`

HasTeams returns a boolean if a field has been set.

### GetEmail

`func (o *UserPrincipal) GetEmail() string`

GetEmail returns the Email field if non-nil, zero value otherwise.

### GetEmailOk

`func (o *UserPrincipal) GetEmailOk() (*string, bool)`

GetEmailOk returns a tuple with the Email field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEmail

`func (o *UserPrincipal) SetEmail(v string)`

SetEmail sets Email field to given value.

### HasEmail

`func (o *UserPrincipal) HasEmail() bool`

HasEmail returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


