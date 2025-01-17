# AffectedComponent

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**IdentityType** | Pointer to **string** |  | [optional] 
**Identity** | Pointer to **string** |  | [optional] 
**VersionType** | Pointer to **string** |  | [optional] 
**Version** | Pointer to **string** |  | [optional] 
**VersionEndExcluding** | Pointer to **string** |  | [optional] 
**VersionEndIncluding** | Pointer to **string** |  | [optional] 
**VersionStartExcluding** | Pointer to **string** |  | [optional] 
**VersionStartIncluding** | Pointer to **string** |  | [optional] 
**Uuid** | Pointer to **string** |  | [optional] 
**AffectedVersionAttributions** | Pointer to [**[]AffectedVersionAttribution**](AffectedVersionAttribution.md) |  | [optional] 

## Methods

### NewAffectedComponent

`func NewAffectedComponent() *AffectedComponent`

NewAffectedComponent instantiates a new AffectedComponent object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAffectedComponentWithDefaults

`func NewAffectedComponentWithDefaults() *AffectedComponent`

NewAffectedComponentWithDefaults instantiates a new AffectedComponent object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetIdentityType

`func (o *AffectedComponent) GetIdentityType() string`

GetIdentityType returns the IdentityType field if non-nil, zero value otherwise.

### GetIdentityTypeOk

`func (o *AffectedComponent) GetIdentityTypeOk() (*string, bool)`

GetIdentityTypeOk returns a tuple with the IdentityType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIdentityType

`func (o *AffectedComponent) SetIdentityType(v string)`

SetIdentityType sets IdentityType field to given value.

### HasIdentityType

`func (o *AffectedComponent) HasIdentityType() bool`

HasIdentityType returns a boolean if a field has been set.

### GetIdentity

`func (o *AffectedComponent) GetIdentity() string`

GetIdentity returns the Identity field if non-nil, zero value otherwise.

### GetIdentityOk

`func (o *AffectedComponent) GetIdentityOk() (*string, bool)`

GetIdentityOk returns a tuple with the Identity field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIdentity

`func (o *AffectedComponent) SetIdentity(v string)`

SetIdentity sets Identity field to given value.

### HasIdentity

`func (o *AffectedComponent) HasIdentity() bool`

HasIdentity returns a boolean if a field has been set.

### GetVersionType

`func (o *AffectedComponent) GetVersionType() string`

GetVersionType returns the VersionType field if non-nil, zero value otherwise.

### GetVersionTypeOk

`func (o *AffectedComponent) GetVersionTypeOk() (*string, bool)`

GetVersionTypeOk returns a tuple with the VersionType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersionType

`func (o *AffectedComponent) SetVersionType(v string)`

SetVersionType sets VersionType field to given value.

### HasVersionType

`func (o *AffectedComponent) HasVersionType() bool`

HasVersionType returns a boolean if a field has been set.

### GetVersion

`func (o *AffectedComponent) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *AffectedComponent) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *AffectedComponent) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *AffectedComponent) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### GetVersionEndExcluding

`func (o *AffectedComponent) GetVersionEndExcluding() string`

GetVersionEndExcluding returns the VersionEndExcluding field if non-nil, zero value otherwise.

### GetVersionEndExcludingOk

`func (o *AffectedComponent) GetVersionEndExcludingOk() (*string, bool)`

GetVersionEndExcludingOk returns a tuple with the VersionEndExcluding field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersionEndExcluding

`func (o *AffectedComponent) SetVersionEndExcluding(v string)`

SetVersionEndExcluding sets VersionEndExcluding field to given value.

### HasVersionEndExcluding

`func (o *AffectedComponent) HasVersionEndExcluding() bool`

HasVersionEndExcluding returns a boolean if a field has been set.

### GetVersionEndIncluding

`func (o *AffectedComponent) GetVersionEndIncluding() string`

GetVersionEndIncluding returns the VersionEndIncluding field if non-nil, zero value otherwise.

### GetVersionEndIncludingOk

`func (o *AffectedComponent) GetVersionEndIncludingOk() (*string, bool)`

GetVersionEndIncludingOk returns a tuple with the VersionEndIncluding field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersionEndIncluding

`func (o *AffectedComponent) SetVersionEndIncluding(v string)`

SetVersionEndIncluding sets VersionEndIncluding field to given value.

### HasVersionEndIncluding

`func (o *AffectedComponent) HasVersionEndIncluding() bool`

HasVersionEndIncluding returns a boolean if a field has been set.

### GetVersionStartExcluding

`func (o *AffectedComponent) GetVersionStartExcluding() string`

GetVersionStartExcluding returns the VersionStartExcluding field if non-nil, zero value otherwise.

### GetVersionStartExcludingOk

`func (o *AffectedComponent) GetVersionStartExcludingOk() (*string, bool)`

GetVersionStartExcludingOk returns a tuple with the VersionStartExcluding field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersionStartExcluding

`func (o *AffectedComponent) SetVersionStartExcluding(v string)`

SetVersionStartExcluding sets VersionStartExcluding field to given value.

### HasVersionStartExcluding

`func (o *AffectedComponent) HasVersionStartExcluding() bool`

HasVersionStartExcluding returns a boolean if a field has been set.

### GetVersionStartIncluding

`func (o *AffectedComponent) GetVersionStartIncluding() string`

GetVersionStartIncluding returns the VersionStartIncluding field if non-nil, zero value otherwise.

### GetVersionStartIncludingOk

`func (o *AffectedComponent) GetVersionStartIncludingOk() (*string, bool)`

GetVersionStartIncludingOk returns a tuple with the VersionStartIncluding field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersionStartIncluding

`func (o *AffectedComponent) SetVersionStartIncluding(v string)`

SetVersionStartIncluding sets VersionStartIncluding field to given value.

### HasVersionStartIncluding

`func (o *AffectedComponent) HasVersionStartIncluding() bool`

HasVersionStartIncluding returns a boolean if a field has been set.

### GetUuid

`func (o *AffectedComponent) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *AffectedComponent) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *AffectedComponent) SetUuid(v string)`

SetUuid sets Uuid field to given value.

### HasUuid

`func (o *AffectedComponent) HasUuid() bool`

HasUuid returns a boolean if a field has been set.

### GetAffectedVersionAttributions

`func (o *AffectedComponent) GetAffectedVersionAttributions() []AffectedVersionAttribution`

GetAffectedVersionAttributions returns the AffectedVersionAttributions field if non-nil, zero value otherwise.

### GetAffectedVersionAttributionsOk

`func (o *AffectedComponent) GetAffectedVersionAttributionsOk() (*[]AffectedVersionAttribution, bool)`

GetAffectedVersionAttributionsOk returns a tuple with the AffectedVersionAttributions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAffectedVersionAttributions

`func (o *AffectedComponent) SetAffectedVersionAttributions(v []AffectedVersionAttribution)`

SetAffectedVersionAttributions sets AffectedVersionAttributions field to given value.

### HasAffectedVersionAttributions

`func (o *AffectedComponent) HasAffectedVersionAttributions() bool`

HasAffectedVersionAttributions returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


