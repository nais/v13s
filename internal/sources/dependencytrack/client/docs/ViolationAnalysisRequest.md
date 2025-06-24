# ViolationAnalysisRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Component** | **string** |  | 
**PolicyViolation** | **string** |  | 
**AnalysisState** | Pointer to **string** |  | [optional] 
**Comment** | Pointer to **string** |  | [optional] 
**IsSuppressed** | Pointer to **bool** |  | [optional] 
**Suppressed** | Pointer to **bool** |  | [optional] 

## Methods

### NewViolationAnalysisRequest

`func NewViolationAnalysisRequest(component string, policyViolation string, ) *ViolationAnalysisRequest`

NewViolationAnalysisRequest instantiates a new ViolationAnalysisRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewViolationAnalysisRequestWithDefaults

`func NewViolationAnalysisRequestWithDefaults() *ViolationAnalysisRequest`

NewViolationAnalysisRequestWithDefaults instantiates a new ViolationAnalysisRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetComponent

`func (o *ViolationAnalysisRequest) GetComponent() string`

GetComponent returns the Component field if non-nil, zero value otherwise.

### GetComponentOk

`func (o *ViolationAnalysisRequest) GetComponentOk() (*string, bool)`

GetComponentOk returns a tuple with the Component field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComponent

`func (o *ViolationAnalysisRequest) SetComponent(v string)`

SetComponent sets Component field to given value.


### GetPolicyViolation

`func (o *ViolationAnalysisRequest) GetPolicyViolation() string`

GetPolicyViolation returns the PolicyViolation field if non-nil, zero value otherwise.

### GetPolicyViolationOk

`func (o *ViolationAnalysisRequest) GetPolicyViolationOk() (*string, bool)`

GetPolicyViolationOk returns a tuple with the PolicyViolation field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolation

`func (o *ViolationAnalysisRequest) SetPolicyViolation(v string)`

SetPolicyViolation sets PolicyViolation field to given value.


### GetAnalysisState

`func (o *ViolationAnalysisRequest) GetAnalysisState() string`

GetAnalysisState returns the AnalysisState field if non-nil, zero value otherwise.

### GetAnalysisStateOk

`func (o *ViolationAnalysisRequest) GetAnalysisStateOk() (*string, bool)`

GetAnalysisStateOk returns a tuple with the AnalysisState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisState

`func (o *ViolationAnalysisRequest) SetAnalysisState(v string)`

SetAnalysisState sets AnalysisState field to given value.

### HasAnalysisState

`func (o *ViolationAnalysisRequest) HasAnalysisState() bool`

HasAnalysisState returns a boolean if a field has been set.

### GetComment

`func (o *ViolationAnalysisRequest) GetComment() string`

GetComment returns the Comment field if non-nil, zero value otherwise.

### GetCommentOk

`func (o *ViolationAnalysisRequest) GetCommentOk() (*string, bool)`

GetCommentOk returns a tuple with the Comment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComment

`func (o *ViolationAnalysisRequest) SetComment(v string)`

SetComment sets Comment field to given value.

### HasComment

`func (o *ViolationAnalysisRequest) HasComment() bool`

HasComment returns a boolean if a field has been set.

### GetIsSuppressed

`func (o *ViolationAnalysisRequest) GetIsSuppressed() bool`

GetIsSuppressed returns the IsSuppressed field if non-nil, zero value otherwise.

### GetIsSuppressedOk

`func (o *ViolationAnalysisRequest) GetIsSuppressedOk() (*bool, bool)`

GetIsSuppressedOk returns a tuple with the IsSuppressed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsSuppressed

`func (o *ViolationAnalysisRequest) SetIsSuppressed(v bool)`

SetIsSuppressed sets IsSuppressed field to given value.

### HasIsSuppressed

`func (o *ViolationAnalysisRequest) HasIsSuppressed() bool`

HasIsSuppressed returns a boolean if a field has been set.

### GetSuppressed

`func (o *ViolationAnalysisRequest) GetSuppressed() bool`

GetSuppressed returns the Suppressed field if non-nil, zero value otherwise.

### GetSuppressedOk

`func (o *ViolationAnalysisRequest) GetSuppressedOk() (*bool, bool)`

GetSuppressedOk returns a tuple with the Suppressed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSuppressed

`func (o *ViolationAnalysisRequest) SetSuppressed(v bool)`

SetSuppressed sets Suppressed field to given value.

### HasSuppressed

`func (o *ViolationAnalysisRequest) HasSuppressed() bool`

HasSuppressed returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


