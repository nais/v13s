# AnalysisRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Project** | Pointer to **string** |  | [optional] 
**Component** | **string** |  | 
**Vulnerability** | **string** |  | 
**AnalysisState** | Pointer to **string** |  | [optional] 
**AnalysisJustification** | Pointer to **string** |  | [optional] 
**AnalysisResponse** | Pointer to **string** |  | [optional] 
**AnalysisDetails** | Pointer to **string** |  | [optional] 
**Comment** | Pointer to **string** |  | [optional] 
**IsSuppressed** | Pointer to **bool** |  | [optional] 
**Suppressed** | Pointer to **bool** |  | [optional] 

## Methods

### NewAnalysisRequest

`func NewAnalysisRequest(component string, vulnerability string, ) *AnalysisRequest`

NewAnalysisRequest instantiates a new AnalysisRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAnalysisRequestWithDefaults

`func NewAnalysisRequestWithDefaults() *AnalysisRequest`

NewAnalysisRequestWithDefaults instantiates a new AnalysisRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetProject

`func (o *AnalysisRequest) GetProject() string`

GetProject returns the Project field if non-nil, zero value otherwise.

### GetProjectOk

`func (o *AnalysisRequest) GetProjectOk() (*string, bool)`

GetProjectOk returns a tuple with the Project field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProject

`func (o *AnalysisRequest) SetProject(v string)`

SetProject sets Project field to given value.

### HasProject

`func (o *AnalysisRequest) HasProject() bool`

HasProject returns a boolean if a field has been set.

### GetComponent

`func (o *AnalysisRequest) GetComponent() string`

GetComponent returns the Component field if non-nil, zero value otherwise.

### GetComponentOk

`func (o *AnalysisRequest) GetComponentOk() (*string, bool)`

GetComponentOk returns a tuple with the Component field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComponent

`func (o *AnalysisRequest) SetComponent(v string)`

SetComponent sets Component field to given value.


### GetVulnerability

`func (o *AnalysisRequest) GetVulnerability() string`

GetVulnerability returns the Vulnerability field if non-nil, zero value otherwise.

### GetVulnerabilityOk

`func (o *AnalysisRequest) GetVulnerabilityOk() (*string, bool)`

GetVulnerabilityOk returns a tuple with the Vulnerability field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerability

`func (o *AnalysisRequest) SetVulnerability(v string)`

SetVulnerability sets Vulnerability field to given value.


### GetAnalysisState

`func (o *AnalysisRequest) GetAnalysisState() string`

GetAnalysisState returns the AnalysisState field if non-nil, zero value otherwise.

### GetAnalysisStateOk

`func (o *AnalysisRequest) GetAnalysisStateOk() (*string, bool)`

GetAnalysisStateOk returns a tuple with the AnalysisState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisState

`func (o *AnalysisRequest) SetAnalysisState(v string)`

SetAnalysisState sets AnalysisState field to given value.

### HasAnalysisState

`func (o *AnalysisRequest) HasAnalysisState() bool`

HasAnalysisState returns a boolean if a field has been set.

### GetAnalysisJustification

`func (o *AnalysisRequest) GetAnalysisJustification() string`

GetAnalysisJustification returns the AnalysisJustification field if non-nil, zero value otherwise.

### GetAnalysisJustificationOk

`func (o *AnalysisRequest) GetAnalysisJustificationOk() (*string, bool)`

GetAnalysisJustificationOk returns a tuple with the AnalysisJustification field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisJustification

`func (o *AnalysisRequest) SetAnalysisJustification(v string)`

SetAnalysisJustification sets AnalysisJustification field to given value.

### HasAnalysisJustification

`func (o *AnalysisRequest) HasAnalysisJustification() bool`

HasAnalysisJustification returns a boolean if a field has been set.

### GetAnalysisResponse

`func (o *AnalysisRequest) GetAnalysisResponse() string`

GetAnalysisResponse returns the AnalysisResponse field if non-nil, zero value otherwise.

### GetAnalysisResponseOk

`func (o *AnalysisRequest) GetAnalysisResponseOk() (*string, bool)`

GetAnalysisResponseOk returns a tuple with the AnalysisResponse field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisResponse

`func (o *AnalysisRequest) SetAnalysisResponse(v string)`

SetAnalysisResponse sets AnalysisResponse field to given value.

### HasAnalysisResponse

`func (o *AnalysisRequest) HasAnalysisResponse() bool`

HasAnalysisResponse returns a boolean if a field has been set.

### GetAnalysisDetails

`func (o *AnalysisRequest) GetAnalysisDetails() string`

GetAnalysisDetails returns the AnalysisDetails field if non-nil, zero value otherwise.

### GetAnalysisDetailsOk

`func (o *AnalysisRequest) GetAnalysisDetailsOk() (*string, bool)`

GetAnalysisDetailsOk returns a tuple with the AnalysisDetails field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAnalysisDetails

`func (o *AnalysisRequest) SetAnalysisDetails(v string)`

SetAnalysisDetails sets AnalysisDetails field to given value.

### HasAnalysisDetails

`func (o *AnalysisRequest) HasAnalysisDetails() bool`

HasAnalysisDetails returns a boolean if a field has been set.

### GetComment

`func (o *AnalysisRequest) GetComment() string`

GetComment returns the Comment field if non-nil, zero value otherwise.

### GetCommentOk

`func (o *AnalysisRequest) GetCommentOk() (*string, bool)`

GetCommentOk returns a tuple with the Comment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComment

`func (o *AnalysisRequest) SetComment(v string)`

SetComment sets Comment field to given value.

### HasComment

`func (o *AnalysisRequest) HasComment() bool`

HasComment returns a boolean if a field has been set.

### GetIsSuppressed

`func (o *AnalysisRequest) GetIsSuppressed() bool`

GetIsSuppressed returns the IsSuppressed field if non-nil, zero value otherwise.

### GetIsSuppressedOk

`func (o *AnalysisRequest) GetIsSuppressedOk() (*bool, bool)`

GetIsSuppressedOk returns a tuple with the IsSuppressed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsSuppressed

`func (o *AnalysisRequest) SetIsSuppressed(v bool)`

SetIsSuppressed sets IsSuppressed field to given value.

### HasIsSuppressed

`func (o *AnalysisRequest) HasIsSuppressed() bool`

HasIsSuppressed returns a boolean if a field has been set.

### GetSuppressed

`func (o *AnalysisRequest) GetSuppressed() bool`

GetSuppressed returns the Suppressed field if non-nil, zero value otherwise.

### GetSuppressedOk

`func (o *AnalysisRequest) GetSuppressedOk() (*bool, bool)`

GetSuppressedOk returns a tuple with the Suppressed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSuppressed

`func (o *AnalysisRequest) SetSuppressed(v bool)`

SetSuppressed sets Suppressed field to given value.

### HasSuppressed

`func (o *AnalysisRequest) HasSuppressed() bool`

HasSuppressed returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


