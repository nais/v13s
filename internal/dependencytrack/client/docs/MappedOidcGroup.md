# MappedOidcGroup

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Group** | Pointer to [**OidcGroup**](OidcGroup.md) |  | [optional] 
**Uuid** | **string** |  | 

## Methods

### NewMappedOidcGroup

`func NewMappedOidcGroup(uuid string, ) *MappedOidcGroup`

NewMappedOidcGroup instantiates a new MappedOidcGroup object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewMappedOidcGroupWithDefaults

`func NewMappedOidcGroupWithDefaults() *MappedOidcGroup`

NewMappedOidcGroupWithDefaults instantiates a new MappedOidcGroup object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetGroup

`func (o *MappedOidcGroup) GetGroup() OidcGroup`

GetGroup returns the Group field if non-nil, zero value otherwise.

### GetGroupOk

`func (o *MappedOidcGroup) GetGroupOk() (*OidcGroup, bool)`

GetGroupOk returns a tuple with the Group field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGroup

`func (o *MappedOidcGroup) SetGroup(v OidcGroup)`

SetGroup sets Group field to given value.

### HasGroup

`func (o *MappedOidcGroup) HasGroup() bool`

HasGroup returns a boolean if a field has been set.

### GetUuid

`func (o *MappedOidcGroup) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *MappedOidcGroup) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *MappedOidcGroup) SetUuid(v string)`

SetUuid sets Uuid field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


