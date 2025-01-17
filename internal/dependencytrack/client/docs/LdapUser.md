# LdapUser

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Username** | Pointer to **string** |  | [optional] 
**Dn** | Pointer to **string** |  | [optional] 
**Teams** | Pointer to [**[]Team**](Team.md) |  | [optional] 
**Email** | Pointer to **string** |  | [optional] 
**Permissions** | Pointer to [**[]Permission**](Permission.md) |  | [optional] 

## Methods

### NewLdapUser

`func NewLdapUser() *LdapUser`

NewLdapUser instantiates a new LdapUser object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewLdapUserWithDefaults

`func NewLdapUserWithDefaults() *LdapUser`

NewLdapUserWithDefaults instantiates a new LdapUser object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetUsername

`func (o *LdapUser) GetUsername() string`

GetUsername returns the Username field if non-nil, zero value otherwise.

### GetUsernameOk

`func (o *LdapUser) GetUsernameOk() (*string, bool)`

GetUsernameOk returns a tuple with the Username field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUsername

`func (o *LdapUser) SetUsername(v string)`

SetUsername sets Username field to given value.

### HasUsername

`func (o *LdapUser) HasUsername() bool`

HasUsername returns a boolean if a field has been set.

### GetDn

`func (o *LdapUser) GetDn() string`

GetDn returns the Dn field if non-nil, zero value otherwise.

### GetDnOk

`func (o *LdapUser) GetDnOk() (*string, bool)`

GetDnOk returns a tuple with the Dn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDn

`func (o *LdapUser) SetDn(v string)`

SetDn sets Dn field to given value.

### HasDn

`func (o *LdapUser) HasDn() bool`

HasDn returns a boolean if a field has been set.

### GetTeams

`func (o *LdapUser) GetTeams() []Team`

GetTeams returns the Teams field if non-nil, zero value otherwise.

### GetTeamsOk

`func (o *LdapUser) GetTeamsOk() (*[]Team, bool)`

GetTeamsOk returns a tuple with the Teams field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTeams

`func (o *LdapUser) SetTeams(v []Team)`

SetTeams sets Teams field to given value.

### HasTeams

`func (o *LdapUser) HasTeams() bool`

HasTeams returns a boolean if a field has been set.

### GetEmail

`func (o *LdapUser) GetEmail() string`

GetEmail returns the Email field if non-nil, zero value otherwise.

### GetEmailOk

`func (o *LdapUser) GetEmailOk() (*string, bool)`

GetEmailOk returns a tuple with the Email field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEmail

`func (o *LdapUser) SetEmail(v string)`

SetEmail sets Email field to given value.

### HasEmail

`func (o *LdapUser) HasEmail() bool`

HasEmail returns a boolean if a field has been set.

### GetPermissions

`func (o *LdapUser) GetPermissions() []Permission`

GetPermissions returns the Permissions field if non-nil, zero value otherwise.

### GetPermissionsOk

`func (o *LdapUser) GetPermissionsOk() (*[]Permission, bool)`

GetPermissionsOk returns a tuple with the Permissions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPermissions

`func (o *LdapUser) SetPermissions(v []Permission)`

SetPermissions sets Permissions field to given value.

### HasPermissions

`func (o *LdapUser) HasPermissions() bool`

HasPermissions returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


