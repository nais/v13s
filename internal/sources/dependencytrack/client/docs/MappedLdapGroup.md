# MappedLdapGroup

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Dn** | Pointer to **string** |  | [optional] 
**Uuid** | **string** |  | 

## Methods

### NewMappedLdapGroup

`func NewMappedLdapGroup(uuid string, ) *MappedLdapGroup`

NewMappedLdapGroup instantiates a new MappedLdapGroup object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewMappedLdapGroupWithDefaults

`func NewMappedLdapGroupWithDefaults() *MappedLdapGroup`

NewMappedLdapGroupWithDefaults instantiates a new MappedLdapGroup object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetDn

`func (o *MappedLdapGroup) GetDn() string`

GetDn returns the Dn field if non-nil, zero value otherwise.

### GetDnOk

`func (o *MappedLdapGroup) GetDnOk() (*string, bool)`

GetDnOk returns a tuple with the Dn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDn

`func (o *MappedLdapGroup) SetDn(v string)`

SetDn sets Dn field to given value.

### HasDn

`func (o *MappedLdapGroup) HasDn() bool`

HasDn returns a boolean if a field has been set.

### GetUuid

`func (o *MappedLdapGroup) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *MappedLdapGroup) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *MappedLdapGroup) SetUuid(v string)`

SetUuid sets Uuid field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


