# PolicyViolation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | Pointer to **string** |  | [optional] 
**Project** | Pointer to [**Project**](Project.md) |  | [optional] 
**Component** | Pointer to [**Component**](Component.md) |  | [optional] 
**PolicyCondition** | Pointer to [**PolicyCondition**](PolicyCondition.md) |  | [optional] 
**Timestamp** | **int64** | UNIX epoch timestamp in milliseconds | 
**Text** | Pointer to **string** |  | [optional] 
**Analysis** | Pointer to [**ViolationAnalysis**](ViolationAnalysis.md) |  | [optional] 
**Uuid** | **string** |  | 

## Methods

### NewPolicyViolation

`func NewPolicyViolation(timestamp int64, uuid string, ) *PolicyViolation`

NewPolicyViolation instantiates a new PolicyViolation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPolicyViolationWithDefaults

`func NewPolicyViolationWithDefaults() *PolicyViolation`

NewPolicyViolationWithDefaults instantiates a new PolicyViolation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *PolicyViolation) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *PolicyViolation) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *PolicyViolation) SetType(v string)`

SetType sets Type field to given value.

### HasType

`func (o *PolicyViolation) HasType() bool`

HasType returns a boolean if a field has been set.

### GetProject

`func (o *PolicyViolation) GetProject() Project`

GetProject returns the Project field if non-nil, zero value otherwise.

### GetProjectOk

`func (o *PolicyViolation) GetProjectOk() (*Project, bool)`

GetProjectOk returns a tuple with the Project field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProject

`func (o *PolicyViolation) SetProject(v Project)`

SetProject sets Project field to given value.

### HasProject

`func (o *PolicyViolation) HasProject() bool`

HasProject returns a boolean if a field has been set.

### GetComponent

`func (o *PolicyViolation) GetComponent() Component`

GetComponent returns the Component field if non-nil, zero value otherwise.

### GetComponentOk

`func (o *PolicyViolation) GetComponentOk() (*Component, bool)`

GetComponentOk returns a tuple with the Component field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComponent

`func (o *PolicyViolation) SetComponent(v Component)`

SetComponent sets Component field to given value.

### HasComponent

`func (o *PolicyViolation) HasComponent() bool`

HasComponent returns a boolean if a field has been set.

### GetPolicyCondition

`func (o *PolicyViolation) GetPolicyCondition() PolicyCondition`

GetPolicyCondition returns the PolicyCondition field if non-nil, zero value otherwise.

### GetPolicyConditionOk

`func (o *PolicyViolation) GetPolicyConditionOk() (*PolicyCondition, bool)`

GetPolicyConditionOk returns a tuple with the PolicyCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyCondition

`func (o *PolicyViolation) SetPolicyCondition(v PolicyCondition)`

SetPolicyCondition sets PolicyCondition field to given value.

### HasPolicyCondition

`func (o *PolicyViolation) HasPolicyCondition() bool`

HasPolicyCondition returns a boolean if a field has been set.

### GetTimestamp

`func (o *PolicyViolation) GetTimestamp() int64`

GetTimestamp returns the Timestamp field if non-nil, zero value otherwise.

### GetTimestampOk

`func (o *PolicyViolation) GetTimestampOk() (*int64, bool)`

GetTimestampOk returns a tuple with the Timestamp field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimestamp

`func (o *PolicyViolation) SetTimestamp(v int64)`

SetTimestamp sets Timestamp field to given value.


### GetText

`func (o *PolicyViolation) GetText() string`

GetText returns the Text field if non-nil, zero value otherwise.

### GetTextOk

`func (o *PolicyViolation) GetTextOk() (*string, bool)`

GetTextOk returns a tuple with the Text field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetText

`func (o *PolicyViolation) SetText(v string)`

SetText sets Text field to given value.

### HasText

`func (o *PolicyViolation) HasText() bool`

HasText returns a boolean if a field has been set.

### GetAnalysis

`func (o *PolicyViolation) GetAnalysis() ViolationAnalysis`

GetAnalysis returns the Analysis field if non-nil, zero value otherwise.

### GetAnalysisOk

`func (o *PolicyViolation) GetAnalysisOk() (*ViolationAnalysis, bool)`

GetAnalysisOk returns a tuple with the Analysis field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysis

`func (o *PolicyViolation) SetAnalysis(v ViolationAnalysis)`

SetAnalysis sets Analysis field to given value.

### HasAnalysis

`func (o *PolicyViolation) HasAnalysis() bool`

HasAnalysis returns a boolean if a field has been set.

### GetUuid

`func (o *PolicyViolation) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *PolicyViolation) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *PolicyViolation) SetUuid(v string)`

SetUuid sets Uuid field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


