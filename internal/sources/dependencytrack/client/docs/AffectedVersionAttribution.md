# AffectedVersionAttribution

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FirstSeen** | **int64** | UNIX epoch timestamp in milliseconds | 
**LastSeen** | **int64** | UNIX epoch timestamp in milliseconds | 
**Source** | Pointer to **string** |  | [optional] 
**Uuid** | Pointer to **string** |  | [optional] 

## Methods

### NewAffectedVersionAttribution

`func NewAffectedVersionAttribution(firstSeen int64, lastSeen int64, ) *AffectedVersionAttribution`

NewAffectedVersionAttribution instantiates a new AffectedVersionAttribution object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAffectedVersionAttributionWithDefaults

`func NewAffectedVersionAttributionWithDefaults() *AffectedVersionAttribution`

NewAffectedVersionAttributionWithDefaults instantiates a new AffectedVersionAttribution object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetFirstSeen

`func (o *AffectedVersionAttribution) GetFirstSeen() int64`

GetFirstSeen returns the FirstSeen field if non-nil, zero value otherwise.

### GetFirstSeenOk

`func (o *AffectedVersionAttribution) GetFirstSeenOk() (*int64, bool)`

GetFirstSeenOk returns a tuple with the FirstSeen field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFirstSeen

`func (o *AffectedVersionAttribution) SetFirstSeen(v int64)`

SetFirstSeen sets FirstSeen field to given value.


### GetLastSeen

`func (o *AffectedVersionAttribution) GetLastSeen() int64`

GetLastSeen returns the LastSeen field if non-nil, zero value otherwise.

### GetLastSeenOk

`func (o *AffectedVersionAttribution) GetLastSeenOk() (*int64, bool)`

GetLastSeenOk returns a tuple with the LastSeen field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastSeen

`func (o *AffectedVersionAttribution) SetLastSeen(v int64)`

SetLastSeen sets LastSeen field to given value.


### GetSource

`func (o *AffectedVersionAttribution) GetSource() string`

GetSource returns the Source field if non-nil, zero value otherwise.

### GetSourceOk

`func (o *AffectedVersionAttribution) GetSourceOk() (*string, bool)`

GetSourceOk returns a tuple with the Source field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSource

`func (o *AffectedVersionAttribution) SetSource(v string)`

SetSource sets Source field to given value.

### HasSource

`func (o *AffectedVersionAttribution) HasSource() bool`

HasSource returns a boolean if a field has been set.

### GetUuid

`func (o *AffectedVersionAttribution) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *AffectedVersionAttribution) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *AffectedVersionAttribution) SetUuid(v string)`

SetUuid sets Uuid field to given value.

### HasUuid

`func (o *AffectedVersionAttribution) HasUuid() bool`

HasUuid returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


