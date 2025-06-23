# ViolationAnalysis

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**AnalysisState** | **string** |  | 
**AnalysisComments** | Pointer to [**[]ViolationAnalysisComment**](ViolationAnalysisComment.md) |  | [optional] 
**ViolationAnalysisState** | Pointer to **string** |  | [optional] 
**IsSuppressed** | Pointer to **bool** |  | [optional] 

## Methods

### NewViolationAnalysis

`func NewViolationAnalysis(analysisState string, ) *ViolationAnalysis`

NewViolationAnalysis instantiates a new ViolationAnalysis object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewViolationAnalysisWithDefaults

`func NewViolationAnalysisWithDefaults() *ViolationAnalysis`

NewViolationAnalysisWithDefaults instantiates a new ViolationAnalysis object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAnalysisState

`func (o *ViolationAnalysis) GetAnalysisState() string`

GetAnalysisState returns the AnalysisState field if non-nil, zero value otherwise.

### GetAnalysisStateOk

`func (o *ViolationAnalysis) GetAnalysisStateOk() (*string, bool)`

GetAnalysisStateOk returns a tuple with the AnalysisState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisState

`func (o *ViolationAnalysis) SetAnalysisState(v string)`

SetAnalysisState sets AnalysisState field to given value.


### GetAnalysisComments

`func (o *ViolationAnalysis) GetAnalysisComments() []ViolationAnalysisComment`

GetAnalysisComments returns the AnalysisComments field if non-nil, zero value otherwise.

### GetAnalysisCommentsOk

`func (o *ViolationAnalysis) GetAnalysisCommentsOk() (*[]ViolationAnalysisComment, bool)`

GetAnalysisCommentsOk returns a tuple with the AnalysisComments field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisComments

`func (o *ViolationAnalysis) SetAnalysisComments(v []ViolationAnalysisComment)`

SetAnalysisComments sets AnalysisComments field to given value.

### HasAnalysisComments

`func (o *ViolationAnalysis) HasAnalysisComments() bool`

HasAnalysisComments returns a boolean if a field has been set.

### GetViolationAnalysisState

`func (o *ViolationAnalysis) GetViolationAnalysisState() string`

GetViolationAnalysisState returns the ViolationAnalysisState field if non-nil, zero value otherwise.

### GetViolationAnalysisStateOk

`func (o *ViolationAnalysis) GetViolationAnalysisStateOk() (*string, bool)`

GetViolationAnalysisStateOk returns a tuple with the ViolationAnalysisState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetViolationAnalysisState

`func (o *ViolationAnalysis) SetViolationAnalysisState(v string)`

SetViolationAnalysisState sets ViolationAnalysisState field to given value.

### HasViolationAnalysisState

`func (o *ViolationAnalysis) HasViolationAnalysisState() bool`

HasViolationAnalysisState returns a boolean if a field has been set.

### GetIsSuppressed

`func (o *ViolationAnalysis) GetIsSuppressed() bool`

GetIsSuppressed returns the IsSuppressed field if non-nil, zero value otherwise.

### GetIsSuppressedOk

`func (o *ViolationAnalysis) GetIsSuppressedOk() (*bool, bool)`

GetIsSuppressedOk returns a tuple with the IsSuppressed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsSuppressed

`func (o *ViolationAnalysis) SetIsSuppressed(v bool)`

SetIsSuppressed sets IsSuppressed field to given value.

### HasIsSuppressed

`func (o *ViolationAnalysis) HasIsSuppressed() bool`

HasIsSuppressed returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


