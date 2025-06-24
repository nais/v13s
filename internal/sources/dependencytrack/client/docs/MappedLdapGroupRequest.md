# MappedLdapGroupRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Team** | **string** |  | 
**Dn** | **string** |  | 

## Methods

### NewMappedLdapGroupRequest

`func NewMappedLdapGroupRequest(team string, dn string, ) *MappedLdapGroupRequest`

NewMappedLdapGroupRequest instantiates a new MappedLdapGroupRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewMappedLdapGroupRequestWithDefaults

`func NewMappedLdapGroupRequestWithDefaults() *MappedLdapGroupRequest`

NewMappedLdapGroupRequestWithDefaults instantiates a new MappedLdapGroupRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTeam

`func (o *MappedLdapGroupRequest) GetTeam() string`

GetTeam returns the Team field if non-nil, zero value otherwise.

### GetTeamOk

`func (o *MappedLdapGroupRequest) GetTeamOk() (*string, bool)`

GetTeamOk returns a tuple with the Team field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTeam

`func (o *MappedLdapGroupRequest) SetTeam(v string)`

SetTeam sets Team field to given value.


### GetDn

`func (o *MappedLdapGroupRequest) GetDn() string`

GetDn returns the Dn field if non-nil, zero value otherwise.

### GetDnOk

`func (o *MappedLdapGroupRequest) GetDnOk() (*string, bool)`

GetDnOk returns a tuple with the Dn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDn

`func (o *MappedLdapGroupRequest) SetDn(v string)`

SetDn sets Dn field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


