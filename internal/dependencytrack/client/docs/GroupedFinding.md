# GroupedFinding

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Vulnerability** | Pointer to **map[string]map[string]interface{}** |  | [optional] 
**Attribution** | Pointer to **map[string]map[string]interface{}** |  | [optional] 

## Methods

### NewGroupedFinding

`func NewGroupedFinding() *GroupedFinding`

NewGroupedFinding instantiates a new GroupedFinding object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewGroupedFindingWithDefaults

`func NewGroupedFindingWithDefaults() *GroupedFinding`

NewGroupedFindingWithDefaults instantiates a new GroupedFinding object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetVulnerability

`func (o *GroupedFinding) GetVulnerability() map[string]map[string]interface{}`

GetVulnerability returns the Vulnerability field if non-nil, zero value otherwise.

### GetVulnerabilityOk

`func (o *GroupedFinding) GetVulnerabilityOk() (*map[string]map[string]interface{}, bool)`

GetVulnerabilityOk returns a tuple with the Vulnerability field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerability

`func (o *GroupedFinding) SetVulnerability(v map[string]map[string]interface{})`

SetVulnerability sets Vulnerability field to given value.

### HasVulnerability

`func (o *GroupedFinding) HasVulnerability() bool`

HasVulnerability returns a boolean if a field has been set.

### GetAttribution

`func (o *GroupedFinding) GetAttribution() map[string]map[string]interface{}`

GetAttribution returns the Attribution field if non-nil, zero value otherwise.

### GetAttributionOk

`func (o *GroupedFinding) GetAttributionOk() (*map[string]map[string]interface{}, bool)`

GetAttributionOk returns a tuple with the Attribution field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttribution

`func (o *GroupedFinding) SetAttribution(v map[string]map[string]interface{})`

SetAttribution sets Attribution field to given value.

### HasAttribution

`func (o *GroupedFinding) HasAttribution() bool`

HasAttribution returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


