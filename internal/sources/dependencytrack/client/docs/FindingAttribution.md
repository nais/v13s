# FindingAttribution

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**AttributedOn** | **int64** | UNIX epoch timestamp in milliseconds | 
**AnalyzerIdentity** | Pointer to **string** |  | [optional] 
**Component** | [**Component**](Component.md) |  | 
**Vulnerability** | [**Vulnerability**](Vulnerability.md) |  | 
**AlternateIdentifier** | Pointer to **string** |  | [optional] 
**ReferenceUrl** | Pointer to **string** |  | [optional] 
**Uuid** | **string** |  | 

## Methods

### NewFindingAttribution

`func NewFindingAttribution(attributedOn int64, component Component, vulnerability Vulnerability, uuid string, ) *FindingAttribution`

NewFindingAttribution instantiates a new FindingAttribution object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewFindingAttributionWithDefaults

`func NewFindingAttributionWithDefaults() *FindingAttribution`

NewFindingAttributionWithDefaults instantiates a new FindingAttribution object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAttributedOn

`func (o *FindingAttribution) GetAttributedOn() int64`

GetAttributedOn returns the AttributedOn field if non-nil, zero value otherwise.

### GetAttributedOnOk

`func (o *FindingAttribution) GetAttributedOnOk() (*int64, bool)`

GetAttributedOnOk returns a tuple with the AttributedOn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributedOn

`func (o *FindingAttribution) SetAttributedOn(v int64)`

SetAttributedOn sets AttributedOn field to given value.


### GetAnalyzerIdentity

`func (o *FindingAttribution) GetAnalyzerIdentity() string`

GetAnalyzerIdentity returns the AnalyzerIdentity field if non-nil, zero value otherwise.

### GetAnalyzerIdentityOk

`func (o *FindingAttribution) GetAnalyzerIdentityOk() (*string, bool)`

GetAnalyzerIdentityOk returns a tuple with the AnalyzerIdentity field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalyzerIdentity

`func (o *FindingAttribution) SetAnalyzerIdentity(v string)`

SetAnalyzerIdentity sets AnalyzerIdentity field to given value.

### HasAnalyzerIdentity

`func (o *FindingAttribution) HasAnalyzerIdentity() bool`

HasAnalyzerIdentity returns a boolean if a field has been set.

### GetComponent

`func (o *FindingAttribution) GetComponent() Component`

GetComponent returns the Component field if non-nil, zero value otherwise.

### GetComponentOk

`func (o *FindingAttribution) GetComponentOk() (*Component, bool)`

GetComponentOk returns a tuple with the Component field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComponent

`func (o *FindingAttribution) SetComponent(v Component)`

SetComponent sets Component field to given value.


### GetVulnerability

`func (o *FindingAttribution) GetVulnerability() Vulnerability`

GetVulnerability returns the Vulnerability field if non-nil, zero value otherwise.

### GetVulnerabilityOk

`func (o *FindingAttribution) GetVulnerabilityOk() (*Vulnerability, bool)`

GetVulnerabilityOk returns a tuple with the Vulnerability field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerability

`func (o *FindingAttribution) SetVulnerability(v Vulnerability)`

SetVulnerability sets Vulnerability field to given value.


### GetAlternateIdentifier

`func (o *FindingAttribution) GetAlternateIdentifier() string`

GetAlternateIdentifier returns the AlternateIdentifier field if non-nil, zero value otherwise.

### GetAlternateIdentifierOk

`func (o *FindingAttribution) GetAlternateIdentifierOk() (*string, bool)`

GetAlternateIdentifierOk returns a tuple with the AlternateIdentifier field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAlternateIdentifier

`func (o *FindingAttribution) SetAlternateIdentifier(v string)`

SetAlternateIdentifier sets AlternateIdentifier field to given value.

### HasAlternateIdentifier

`func (o *FindingAttribution) HasAlternateIdentifier() bool`

HasAlternateIdentifier returns a boolean if a field has been set.

### GetReferenceUrl

`func (o *FindingAttribution) GetReferenceUrl() string`

GetReferenceUrl returns the ReferenceUrl field if non-nil, zero value otherwise.

### GetReferenceUrlOk

`func (o *FindingAttribution) GetReferenceUrlOk() (*string, bool)`

GetReferenceUrlOk returns a tuple with the ReferenceUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReferenceUrl

`func (o *FindingAttribution) SetReferenceUrl(v string)`

SetReferenceUrl sets ReferenceUrl field to given value.

### HasReferenceUrl

`func (o *FindingAttribution) HasReferenceUrl() bool`

HasReferenceUrl returns a boolean if a field has been set.

### GetUuid

`func (o *FindingAttribution) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *FindingAttribution) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *FindingAttribution) SetUuid(v string)`

SetUuid sets Uuid field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


