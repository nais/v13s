# Team

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Uuid** | **string** |  | 
**Name** | Pointer to **string** |  | [optional] 
**ApiKeys** | Pointer to [**[]ApiKey**](ApiKey.md) |  | [optional] 
**LdapUsers** | Pointer to [**[]LdapUser**](LdapUser.md) |  | [optional] 
**ManagedUsers** | Pointer to [**[]ManagedUser**](ManagedUser.md) |  | [optional] 
**OidcUsers** | Pointer to [**[]OidcUser**](OidcUser.md) |  | [optional] 
**MappedLdapGroups** | Pointer to [**[]MappedLdapGroup**](MappedLdapGroup.md) |  | [optional] 
**MappedOidcGroups** | Pointer to [**[]MappedOidcGroup**](MappedOidcGroup.md) |  | [optional] 
**Permissions** | Pointer to [**[]Permission**](Permission.md) |  | [optional] 

## Methods

### NewTeam

`func NewTeam(uuid string, ) *Team`

NewTeam instantiates a new Team object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewTeamWithDefaults

`func NewTeamWithDefaults() *Team`

NewTeamWithDefaults instantiates a new Team object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetUuid

`func (o *Team) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *Team) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *Team) SetUuid(v string)`

SetUuid sets Uuid field to given value.


### GetName

`func (o *Team) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *Team) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *Team) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *Team) HasName() bool`

HasName returns a boolean if a field has been set.

### GetApiKeys

`func (o *Team) GetApiKeys() []ApiKey`

GetApiKeys returns the ApiKeys field if non-nil, zero value otherwise.

### GetApiKeysOk

`func (o *Team) GetApiKeysOk() (*[]ApiKey, bool)`

GetApiKeysOk returns a tuple with the ApiKeys field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetApiKeys

`func (o *Team) SetApiKeys(v []ApiKey)`

SetApiKeys sets ApiKeys field to given value.

### HasApiKeys

`func (o *Team) HasApiKeys() bool`

HasApiKeys returns a boolean if a field has been set.

### GetLdapUsers

`func (o *Team) GetLdapUsers() []LdapUser`

GetLdapUsers returns the LdapUsers field if non-nil, zero value otherwise.

### GetLdapUsersOk

`func (o *Team) GetLdapUsersOk() (*[]LdapUser, bool)`

GetLdapUsersOk returns a tuple with the LdapUsers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLdapUsers

`func (o *Team) SetLdapUsers(v []LdapUser)`

SetLdapUsers sets LdapUsers field to given value.

### HasLdapUsers

`func (o *Team) HasLdapUsers() bool`

HasLdapUsers returns a boolean if a field has been set.

### GetManagedUsers

`func (o *Team) GetManagedUsers() []ManagedUser`

GetManagedUsers returns the ManagedUsers field if non-nil, zero value otherwise.

### GetManagedUsersOk

`func (o *Team) GetManagedUsersOk() (*[]ManagedUser, bool)`

GetManagedUsersOk returns a tuple with the ManagedUsers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetManagedUsers

`func (o *Team) SetManagedUsers(v []ManagedUser)`

SetManagedUsers sets ManagedUsers field to given value.

### HasManagedUsers

`func (o *Team) HasManagedUsers() bool`

HasManagedUsers returns a boolean if a field has been set.

### GetOidcUsers

`func (o *Team) GetOidcUsers() []OidcUser`

GetOidcUsers returns the OidcUsers field if non-nil, zero value otherwise.

### GetOidcUsersOk

`func (o *Team) GetOidcUsersOk() (*[]OidcUser, bool)`

GetOidcUsersOk returns a tuple with the OidcUsers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOidcUsers

`func (o *Team) SetOidcUsers(v []OidcUser)`

SetOidcUsers sets OidcUsers field to given value.

### HasOidcUsers

`func (o *Team) HasOidcUsers() bool`

HasOidcUsers returns a boolean if a field has been set.

### GetMappedLdapGroups

`func (o *Team) GetMappedLdapGroups() []MappedLdapGroup`

GetMappedLdapGroups returns the MappedLdapGroups field if non-nil, zero value otherwise.

### GetMappedLdapGroupsOk

`func (o *Team) GetMappedLdapGroupsOk() (*[]MappedLdapGroup, bool)`

GetMappedLdapGroupsOk returns a tuple with the MappedLdapGroups field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMappedLdapGroups

`func (o *Team) SetMappedLdapGroups(v []MappedLdapGroup)`

SetMappedLdapGroups sets MappedLdapGroups field to given value.

### HasMappedLdapGroups

`func (o *Team) HasMappedLdapGroups() bool`

HasMappedLdapGroups returns a boolean if a field has been set.

### GetMappedOidcGroups

`func (o *Team) GetMappedOidcGroups() []MappedOidcGroup`

GetMappedOidcGroups returns the MappedOidcGroups field if non-nil, zero value otherwise.

### GetMappedOidcGroupsOk

`func (o *Team) GetMappedOidcGroupsOk() (*[]MappedOidcGroup, bool)`

GetMappedOidcGroupsOk returns a tuple with the MappedOidcGroups field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMappedOidcGroups

`func (o *Team) SetMappedOidcGroups(v []MappedOidcGroup)`

SetMappedOidcGroups sets MappedOidcGroups field to given value.

### HasMappedOidcGroups

`func (o *Team) HasMappedOidcGroups() bool`

HasMappedOidcGroups returns a boolean if a field has been set.

### GetPermissions

`func (o *Team) GetPermissions() []Permission`

GetPermissions returns the Permissions field if non-nil, zero value otherwise.

### GetPermissionsOk

`func (o *Team) GetPermissionsOk() (*[]Permission, bool)`

GetPermissionsOk returns a tuple with the Permissions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPermissions

`func (o *Team) SetPermissions(v []Permission)`

SetPermissions sets Permissions field to given value.

### HasPermissions

`func (o *Team) HasPermissions() bool`

HasPermissions returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


