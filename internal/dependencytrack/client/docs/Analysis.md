# Analysis

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**AnalysisState** | **string** |  | 
**AnalysisJustification** | **string** |  | 
**AnalysisResponse** | **string** |  | 
**AnalysisDetails** | **string** |  | 
**AnalysisComments** | Pointer to [**[]AnalysisComment**](AnalysisComment.md) |  | [optional] 
**IsSuppressed** | Pointer to **bool** |  | [optional] 

## Methods

### NewAnalysis

`func NewAnalysis(analysisState string, analysisJustification string, analysisResponse string, analysisDetails string, ) *Analysis`

NewAnalysis instantiates a new Analysis object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAnalysisWithDefaults

`func NewAnalysisWithDefaults() *Analysis`

NewAnalysisWithDefaults instantiates a new Analysis object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAnalysisState

`func (o *Analysis) GetAnalysisState() string`

GetAnalysisState returns the AnalysisState field if non-nil, zero value otherwise.

### GetAnalysisStateOk

`func (o *Analysis) GetAnalysisStateOk() (*string, bool)`

GetAnalysisStateOk returns a tuple with the AnalysisState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisState

`func (o *Analysis) SetAnalysisState(v string)`

SetAnalysisState sets AnalysisState field to given value.


### GetAnalysisJustification

`func (o *Analysis) GetAnalysisJustification() string`

GetAnalysisJustification returns the AnalysisJustification field if non-nil, zero value otherwise.

### GetAnalysisJustificationOk

`func (o *Analysis) GetAnalysisJustificationOk() (*string, bool)`

GetAnalysisJustificationOk returns a tuple with the AnalysisJustification field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisJustification

`func (o *Analysis) SetAnalysisJustification(v string)`

SetAnalysisJustification sets AnalysisJustification field to given value.


### GetAnalysisResponse

`func (o *Analysis) GetAnalysisResponse() string`

GetAnalysisResponse returns the AnalysisResponse field if non-nil, zero value otherwise.

### GetAnalysisResponseOk

`func (o *Analysis) GetAnalysisResponseOk() (*string, bool)`

GetAnalysisResponseOk returns a tuple with the AnalysisResponse field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisResponse

`func (o *Analysis) SetAnalysisResponse(v string)`

SetAnalysisResponse sets AnalysisResponse field to given value.


### GetAnalysisDetails

`func (o *Analysis) GetAnalysisDetails() string`

GetAnalysisDetails returns the AnalysisDetails field if non-nil, zero value otherwise.

### GetAnalysisDetailsOk

`func (o *Analysis) GetAnalysisDetailsOk() (*string, bool)`

GetAnalysisDetailsOk returns a tuple with the AnalysisDetails field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisDetails

`func (o *Analysis) SetAnalysisDetails(v string)`

SetAnalysisDetails sets AnalysisDetails field to given value.


### GetAnalysisComments

`func (o *Analysis) GetAnalysisComments() []AnalysisComment`

GetAnalysisComments returns the AnalysisComments field if non-nil, zero value otherwise.

### GetAnalysisCommentsOk

`func (o *Analysis) GetAnalysisCommentsOk() (*[]AnalysisComment, bool)`

GetAnalysisCommentsOk returns a tuple with the AnalysisComments field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisComments

`func (o *Analysis) SetAnalysisComments(v []AnalysisComment)`

SetAnalysisComments sets AnalysisComments field to given value.

### HasAnalysisComments

`func (o *Analysis) HasAnalysisComments() bool`

HasAnalysisComments returns a boolean if a field has been set.

### GetIsSuppressed

`func (o *Analysis) GetIsSuppressed() bool`

GetIsSuppressed returns the IsSuppressed field if non-nil, zero value otherwise.

### GetIsSuppressedOk

`func (o *Analysis) GetIsSuppressedOk() (*bool, bool)`

GetIsSuppressedOk returns a tuple with the IsSuppressed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsSuppressed

`func (o *Analysis) SetIsSuppressed(v bool)`

SetIsSuppressed sets IsSuppressed field to given value.

### HasIsSuppressed

`func (o *Analysis) HasIsSuppressed() bool`

HasIsSuppressed returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


