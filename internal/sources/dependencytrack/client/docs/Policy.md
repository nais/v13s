# Policy

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**Operator** | Pointer to **string** |  | [optional] 
**ViolationState** | Pointer to **string** |  | [optional] 
**PolicyConditions** | Pointer to [**[]PolicyCondition**](PolicyCondition.md) |  | [optional] 
**Projects** | Pointer to [**[]Project**](Project.md) |  | [optional] 
**Tags** | Pointer to [**[]Tag**](Tag.md) |  | [optional] 
**Uuid** | **string** |  | 
**IncludeChildren** | Pointer to **bool** |  | [optional] 
**OnlyLatestProjectVersion** | Pointer to **bool** |  | [optional] 
**Global** | Pointer to **bool** |  | [optional] 

## Methods

### NewPolicy

`func NewPolicy(uuid string, ) *Policy`

NewPolicy instantiates a new Policy object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPolicyWithDefaults

`func NewPolicyWithDefaults() *Policy`

NewPolicyWithDefaults instantiates a new Policy object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *Policy) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *Policy) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *Policy) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *Policy) HasName() bool`

HasName returns a boolean if a field has been set.

### GetOperator

`func (o *Policy) GetOperator() string`

GetOperator returns the Operator field if non-nil, zero value otherwise.

### GetOperatorOk

`func (o *Policy) GetOperatorOk() (*string, bool)`

GetOperatorOk returns a tuple with the Operator field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOperator

`func (o *Policy) SetOperator(v string)`

SetOperator sets Operator field to given value.

### HasOperator

`func (o *Policy) HasOperator() bool`

HasOperator returns a boolean if a field has been set.

### GetViolationState

`func (o *Policy) GetViolationState() string`

GetViolationState returns the ViolationState field if non-nil, zero value otherwise.

### GetViolationStateOk

`func (o *Policy) GetViolationStateOk() (*string, bool)`

GetViolationStateOk returns a tuple with the ViolationState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetViolationState

`func (o *Policy) SetViolationState(v string)`

SetViolationState sets ViolationState field to given value.

### HasViolationState

`func (o *Policy) HasViolationState() bool`

HasViolationState returns a boolean if a field has been set.

### GetPolicyConditions

`func (o *Policy) GetPolicyConditions() []PolicyCondition`

GetPolicyConditions returns the PolicyConditions field if non-nil, zero value otherwise.

### GetPolicyConditionsOk

`func (o *Policy) GetPolicyConditionsOk() (*[]PolicyCondition, bool)`

GetPolicyConditionsOk returns a tuple with the PolicyConditions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyConditions

`func (o *Policy) SetPolicyConditions(v []PolicyCondition)`

SetPolicyConditions sets PolicyConditions field to given value.

### HasPolicyConditions

`func (o *Policy) HasPolicyConditions() bool`

HasPolicyConditions returns a boolean if a field has been set.

### GetProjects

`func (o *Policy) GetProjects() []Project`

GetProjects returns the Projects field if non-nil, zero value otherwise.

### GetProjectsOk

`func (o *Policy) GetProjectsOk() (*[]Project, bool)`

GetProjectsOk returns a tuple with the Projects field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProjects

`func (o *Policy) SetProjects(v []Project)`

SetProjects sets Projects field to given value.

### HasProjects

`func (o *Policy) HasProjects() bool`

HasProjects returns a boolean if a field has been set.

### GetTags

`func (o *Policy) GetTags() []Tag`

GetTags returns the Tags field if non-nil, zero value otherwise.

### GetTagsOk

`func (o *Policy) GetTagsOk() (*[]Tag, bool)`

GetTagsOk returns a tuple with the Tags field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTags

`func (o *Policy) SetTags(v []Tag)`

SetTags sets Tags field to given value.

### HasTags

`func (o *Policy) HasTags() bool`

HasTags returns a boolean if a field has been set.

### GetUuid

`func (o *Policy) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *Policy) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *Policy) SetUuid(v string)`

SetUuid sets Uuid field to given value.


### GetIncludeChildren

`func (o *Policy) GetIncludeChildren() bool`

GetIncludeChildren returns the IncludeChildren field if non-nil, zero value otherwise.

### GetIncludeChildrenOk

`func (o *Policy) GetIncludeChildrenOk() (*bool, bool)`

GetIncludeChildrenOk returns a tuple with the IncludeChildren field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludeChildren

`func (o *Policy) SetIncludeChildren(v bool)`

SetIncludeChildren sets IncludeChildren field to given value.

### HasIncludeChildren

`func (o *Policy) HasIncludeChildren() bool`

HasIncludeChildren returns a boolean if a field has been set.

### GetOnlyLatestProjectVersion

`func (o *Policy) GetOnlyLatestProjectVersion() bool`

GetOnlyLatestProjectVersion returns the OnlyLatestProjectVersion field if non-nil, zero value otherwise.

### GetOnlyLatestProjectVersionOk

`func (o *Policy) GetOnlyLatestProjectVersionOk() (*bool, bool)`

GetOnlyLatestProjectVersionOk returns a tuple with the OnlyLatestProjectVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOnlyLatestProjectVersion

`func (o *Policy) SetOnlyLatestProjectVersion(v bool)`

SetOnlyLatestProjectVersion sets OnlyLatestProjectVersion field to given value.

### HasOnlyLatestProjectVersion

`func (o *Policy) HasOnlyLatestProjectVersion() bool`

HasOnlyLatestProjectVersion returns a boolean if a field has been set.

### GetGlobal

`func (o *Policy) GetGlobal() bool`

GetGlobal returns the Global field if non-nil, zero value otherwise.

### GetGlobalOk

`func (o *Policy) GetGlobalOk() (*bool, bool)`

GetGlobalOk returns a tuple with the Global field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGlobal

`func (o *Policy) SetGlobal(v bool)`

SetGlobal sets Global field to given value.

### HasGlobal

`func (o *Policy) HasGlobal() bool`

HasGlobal returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


