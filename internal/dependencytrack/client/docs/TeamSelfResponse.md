# TeamSelfResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Uuid** | Pointer to **string** |  | [optional] 
**Name** | Pointer to **string** |  | [optional] 
**Permissions** | Pointer to [**[]Permission**](Permission.md) |  | [optional] 

## Methods

### NewTeamSelfResponse

`func NewTeamSelfResponse() *TeamSelfResponse`

NewTeamSelfResponse instantiates a new TeamSelfResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewTeamSelfResponseWithDefaults

`func NewTeamSelfResponseWithDefaults() *TeamSelfResponse`

NewTeamSelfResponseWithDefaults instantiates a new TeamSelfResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetUuid

`func (o *TeamSelfResponse) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *TeamSelfResponse) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *TeamSelfResponse) SetUuid(v string)`

SetUuid sets Uuid field to given value.

### HasUuid

`func (o *TeamSelfResponse) HasUuid() bool`

HasUuid returns a boolean if a field has been set.

### GetName

`func (o *TeamSelfResponse) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *TeamSelfResponse) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *TeamSelfResponse) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *TeamSelfResponse) HasName() bool`

HasName returns a boolean if a field has been set.

### GetPermissions

`func (o *TeamSelfResponse) GetPermissions() []Permission`

GetPermissions returns the Permissions field if non-nil, zero value otherwise.

### GetPermissionsOk

`func (o *TeamSelfResponse) GetPermissionsOk() (*[]Permission, bool)`

GetPermissionsOk returns a tuple with the Permissions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPermissions

`func (o *TeamSelfResponse) SetPermissions(v []Permission)`

SetPermissions sets Permissions field to given value.

### HasPermissions

`func (o *TeamSelfResponse) HasPermissions() bool`

HasPermissions returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


