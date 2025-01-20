# Finding

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Component** | Pointer to **map[string]interface{}** |  | [optional] 
**Vulnerability** | Pointer to **map[string]interface{}** |  | [optional] 
**Analysis** | Pointer to **map[string]interface{}** |  | [optional] 
**Attribution** | Pointer to **map[string]interface{}** |  | [optional] 
**Matrix** | Pointer to **string** |  | [optional] 

## Methods

### NewFinding

`func NewFinding() *Finding`

NewFinding instantiates a new Finding object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewFindingWithDefaults

`func NewFindingWithDefaults() *Finding`

NewFindingWithDefaults instantiates a new Finding object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetComponent

`func (o *Finding) GetComponent() map[string]interface{}`

GetComponent returns the Component field if non-nil, zero value otherwise.

### GetComponentOk

`func (o *Finding) GetComponentOk() (*map[string]interface{}, bool)`

GetComponentOk returns a tuple with the Component field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComponent

`func (o *Finding) SetComponent(v map[string]interface{})`

SetComponent sets Component field to given value.

### HasComponent

`func (o *Finding) HasComponent() bool`

HasComponent returns a boolean if a field has been set.

### GetVulnerability

`func (o *Finding) GetVulnerability() map[string]interface{}`

GetVulnerability returns the Vulnerability field if non-nil, zero value otherwise.

### GetVulnerabilityOk

`func (o *Finding) GetVulnerabilityOk() (*map[string]interface{}, bool)`

GetVulnerabilityOk returns a tuple with the Vulnerability field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerability

`func (o *Finding) SetVulnerability(v map[string]interface{})`

SetVulnerability sets Vulnerability field to given value.

### HasVulnerability

`func (o *Finding) HasVulnerability() bool`

HasVulnerability returns a boolean if a field has been set.

### GetAnalysis

`func (o *Finding) GetAnalysis() map[string]interface{}`

GetAnalysis returns the Analysis field if non-nil, zero value otherwise.

### GetAnalysisOk

`func (o *Finding) GetAnalysisOk() (*map[string]interface{}, bool)`

GetAnalysisOk returns a tuple with the Analysis field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysis

`func (o *Finding) SetAnalysis(v map[string]interface{})`

SetAnalysis sets Analysis field to given value.

### HasAnalysis

`func (o *Finding) HasAnalysis() bool`

HasAnalysis returns a boolean if a field has been set.

### GetAttribution

`func (o *Finding) GetAttribution() map[string]interface{}`

GetAttribution returns the Attribution field if non-nil, zero value otherwise.

### GetAttributionOk

`func (o *Finding) GetAttributionOk() (*map[string]interface{}, bool)`

GetAttributionOk returns a tuple with the Attribution field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttribution

`func (o *Finding) SetAttribution(v map[string]interface{})`

SetAttribution sets Attribution field to given value.

### HasAttribution

`func (o *Finding) HasAttribution() bool`

HasAttribution returns a boolean if a field has been set.

### GetMatrix

`func (o *Finding) GetMatrix() string`

GetMatrix returns the Matrix field if non-nil, zero value otherwise.

### GetMatrixOk

`func (o *Finding) GetMatrixOk() (*string, bool)`

GetMatrixOk returns a tuple with the Matrix field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMatrix

`func (o *Finding) SetMatrix(v string)`

SetMatrix sets Matrix field to given value.

### HasMatrix

`func (o *Finding) HasMatrix() bool`

HasMatrix returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


