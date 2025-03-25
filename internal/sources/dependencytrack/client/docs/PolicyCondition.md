# PolicyCondition

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Policy** | Pointer to [**Policy**](Policy.md) |  | [optional] 
**Operator** | Pointer to **string** |  | [optional] 
**Subject** | Pointer to **string** |  | [optional] 
**Value** | Pointer to **string** |  | [optional] 
**Uuid** | **string** |  | 

## Methods

### NewPolicyCondition

`func NewPolicyCondition(uuid string, ) *PolicyCondition`

NewPolicyCondition instantiates a new PolicyCondition object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPolicyConditionWithDefaults

`func NewPolicyConditionWithDefaults() *PolicyCondition`

NewPolicyConditionWithDefaults instantiates a new PolicyCondition object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPolicy

`func (o *PolicyCondition) GetPolicy() Policy`

GetPolicy returns the Policy field if non-nil, zero value otherwise.

### GetPolicyOk

`func (o *PolicyCondition) GetPolicyOk() (*Policy, bool)`

GetPolicyOk returns a tuple with the Policy field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicy

`func (o *PolicyCondition) SetPolicy(v Policy)`

SetPolicy sets Policy field to given value.

### HasPolicy

`func (o *PolicyCondition) HasPolicy() bool`

HasPolicy returns a boolean if a field has been set.

### GetOperator

`func (o *PolicyCondition) GetOperator() string`

GetOperator returns the Operator field if non-nil, zero value otherwise.

### GetOperatorOk

`func (o *PolicyCondition) GetOperatorOk() (*string, bool)`

GetOperatorOk returns a tuple with the Operator field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOperator

`func (o *PolicyCondition) SetOperator(v string)`

SetOperator sets Operator field to given value.

### HasOperator

`func (o *PolicyCondition) HasOperator() bool`

HasOperator returns a boolean if a field has been set.

### GetSubject

`func (o *PolicyCondition) GetSubject() string`

GetSubject returns the Subject field if non-nil, zero value otherwise.

### GetSubjectOk

`func (o *PolicyCondition) GetSubjectOk() (*string, bool)`

GetSubjectOk returns a tuple with the Subject field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubject

`func (o *PolicyCondition) SetSubject(v string)`

SetSubject sets Subject field to given value.

### HasSubject

`func (o *PolicyCondition) HasSubject() bool`

HasSubject returns a boolean if a field has been set.

### GetValue

`func (o *PolicyCondition) GetValue() string`

GetValue returns the Value field if non-nil, zero value otherwise.

### GetValueOk

`func (o *PolicyCondition) GetValueOk() (*string, bool)`

GetValueOk returns a tuple with the Value field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetValue

`func (o *PolicyCondition) SetValue(v string)`

SetValue sets Value field to given value.

### HasValue

`func (o *PolicyCondition) HasValue() bool`

HasValue returns a boolean if a field has been set.

### GetUuid

`func (o *PolicyCondition) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *PolicyCondition) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *PolicyCondition) SetUuid(v string)`

SetUuid sets Uuid field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


