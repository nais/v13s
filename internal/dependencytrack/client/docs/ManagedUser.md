# ManagedUser

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Username** | Pointer to **string** |  | [optional] 
**LastPasswordChange** | **int64** |  | 
**Fullname** | Pointer to **string** |  | [optional] 
**Email** | Pointer to **string** |  | [optional] 
**Suspended** | Pointer to **bool** |  | [optional] 
**ForcePasswordChange** | Pointer to **bool** |  | [optional] 
**NonExpiryPassword** | Pointer to **bool** |  | [optional] 
**Teams** | Pointer to [**[]Team**](Team.md) |  | [optional] 
**Permissions** | Pointer to [**[]Permission**](Permission.md) |  | [optional] 
**NewPassword** | Pointer to **string** |  | [optional] 
**ConfirmPassword** | Pointer to **string** |  | [optional] 

## Methods

### NewManagedUser

`func NewManagedUser(lastPasswordChange int64, ) *ManagedUser`

NewManagedUser instantiates a new ManagedUser object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewManagedUserWithDefaults

`func NewManagedUserWithDefaults() *ManagedUser`

NewManagedUserWithDefaults instantiates a new ManagedUser object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetUsername

`func (o *ManagedUser) GetUsername() string`

GetUsername returns the Username field if non-nil, zero value otherwise.

### GetUsernameOk

`func (o *ManagedUser) GetUsernameOk() (*string, bool)`

GetUsernameOk returns a tuple with the Username field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUsername

`func (o *ManagedUser) SetUsername(v string)`

SetUsername sets Username field to given value.

### HasUsername

`func (o *ManagedUser) HasUsername() bool`

HasUsername returns a boolean if a field has been set.

### GetLastPasswordChange

`func (o *ManagedUser) GetLastPasswordChange() int64`

GetLastPasswordChange returns the LastPasswordChange field if non-nil, zero value otherwise.

### GetLastPasswordChangeOk

`func (o *ManagedUser) GetLastPasswordChangeOk() (*int64, bool)`

GetLastPasswordChangeOk returns a tuple with the LastPasswordChange field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastPasswordChange

`func (o *ManagedUser) SetLastPasswordChange(v int64)`

SetLastPasswordChange sets LastPasswordChange field to given value.


### GetFullname

`func (o *ManagedUser) GetFullname() string`

GetFullname returns the Fullname field if non-nil, zero value otherwise.

### GetFullnameOk

`func (o *ManagedUser) GetFullnameOk() (*string, bool)`

GetFullnameOk returns a tuple with the Fullname field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFullname

`func (o *ManagedUser) SetFullname(v string)`

SetFullname sets Fullname field to given value.

### HasFullname

`func (o *ManagedUser) HasFullname() bool`

HasFullname returns a boolean if a field has been set.

### GetEmail

`func (o *ManagedUser) GetEmail() string`

GetEmail returns the Email field if non-nil, zero value otherwise.

### GetEmailOk

`func (o *ManagedUser) GetEmailOk() (*string, bool)`

GetEmailOk returns a tuple with the Email field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEmail

`func (o *ManagedUser) SetEmail(v string)`

SetEmail sets Email field to given value.

### HasEmail

`func (o *ManagedUser) HasEmail() bool`

HasEmail returns a boolean if a field has been set.

### GetSuspended

`func (o *ManagedUser) GetSuspended() bool`

GetSuspended returns the Suspended field if non-nil, zero value otherwise.

### GetSuspendedOk

`func (o *ManagedUser) GetSuspendedOk() (*bool, bool)`

GetSuspendedOk returns a tuple with the Suspended field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSuspended

`func (o *ManagedUser) SetSuspended(v bool)`

SetSuspended sets Suspended field to given value.

### HasSuspended

`func (o *ManagedUser) HasSuspended() bool`

HasSuspended returns a boolean if a field has been set.

### GetForcePasswordChange

`func (o *ManagedUser) GetForcePasswordChange() bool`

GetForcePasswordChange returns the ForcePasswordChange field if non-nil, zero value otherwise.

### GetForcePasswordChangeOk

`func (o *ManagedUser) GetForcePasswordChangeOk() (*bool, bool)`

GetForcePasswordChangeOk returns a tuple with the ForcePasswordChange field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetForcePasswordChange

`func (o *ManagedUser) SetForcePasswordChange(v bool)`

SetForcePasswordChange sets ForcePasswordChange field to given value.

### HasForcePasswordChange

`func (o *ManagedUser) HasForcePasswordChange() bool`

HasForcePasswordChange returns a boolean if a field has been set.

### GetNonExpiryPassword

`func (o *ManagedUser) GetNonExpiryPassword() bool`

GetNonExpiryPassword returns the NonExpiryPassword field if non-nil, zero value otherwise.

### GetNonExpiryPasswordOk

`func (o *ManagedUser) GetNonExpiryPasswordOk() (*bool, bool)`

GetNonExpiryPasswordOk returns a tuple with the NonExpiryPassword field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNonExpiryPassword

`func (o *ManagedUser) SetNonExpiryPassword(v bool)`

SetNonExpiryPassword sets NonExpiryPassword field to given value.

### HasNonExpiryPassword

`func (o *ManagedUser) HasNonExpiryPassword() bool`

HasNonExpiryPassword returns a boolean if a field has been set.

### GetTeams

`func (o *ManagedUser) GetTeams() []Team`

GetTeams returns the Teams field if non-nil, zero value otherwise.

### GetTeamsOk

`func (o *ManagedUser) GetTeamsOk() (*[]Team, bool)`

GetTeamsOk returns a tuple with the Teams field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTeams

`func (o *ManagedUser) SetTeams(v []Team)`

SetTeams sets Teams field to given value.

### HasTeams

`func (o *ManagedUser) HasTeams() bool`

HasTeams returns a boolean if a field has been set.

### GetPermissions

`func (o *ManagedUser) GetPermissions() []Permission`

GetPermissions returns the Permissions field if non-nil, zero value otherwise.

### GetPermissionsOk

`func (o *ManagedUser) GetPermissionsOk() (*[]Permission, bool)`

GetPermissionsOk returns a tuple with the Permissions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPermissions

`func (o *ManagedUser) SetPermissions(v []Permission)`

SetPermissions sets Permissions field to given value.

### HasPermissions

`func (o *ManagedUser) HasPermissions() bool`

HasPermissions returns a boolean if a field has been set.

### GetNewPassword

`func (o *ManagedUser) GetNewPassword() string`

GetNewPassword returns the NewPassword field if non-nil, zero value otherwise.

### GetNewPasswordOk

`func (o *ManagedUser) GetNewPasswordOk() (*string, bool)`

GetNewPasswordOk returns a tuple with the NewPassword field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNewPassword

`func (o *ManagedUser) SetNewPassword(v string)`

SetNewPassword sets NewPassword field to given value.

### HasNewPassword

`func (o *ManagedUser) HasNewPassword() bool`

HasNewPassword returns a boolean if a field has been set.

### GetConfirmPassword

`func (o *ManagedUser) GetConfirmPassword() string`

GetConfirmPassword returns the ConfirmPassword field if non-nil, zero value otherwise.

### GetConfirmPasswordOk

`func (o *ManagedUser) GetConfirmPasswordOk() (*string, bool)`

GetConfirmPasswordOk returns a tuple with the ConfirmPassword field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetConfirmPassword

`func (o *ManagedUser) SetConfirmPassword(v string)`

SetConfirmPassword sets ConfirmPassword field to given value.

### HasConfirmPassword

`func (o *ManagedUser) HasConfirmPassword() bool`

HasConfirmPassword returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


