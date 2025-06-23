# AnalysisComment

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Timestamp** | **int64** | UNIX epoch timestamp in milliseconds | 
**Comment** | **string** |  | 
**Commenter** | Pointer to **string** |  | [optional] 

## Methods

### NewAnalysisComment

`func NewAnalysisComment(timestamp int64, comment string, ) *AnalysisComment`

NewAnalysisComment instantiates a new AnalysisComment object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAnalysisCommentWithDefaults

`func NewAnalysisCommentWithDefaults() *AnalysisComment`

NewAnalysisCommentWithDefaults instantiates a new AnalysisComment object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTimestamp

`func (o *AnalysisComment) GetTimestamp() int64`

GetTimestamp returns the Timestamp field if non-nil, zero value otherwise.

### GetTimestampOk

`func (o *AnalysisComment) GetTimestampOk() (*int64, bool)`

GetTimestampOk returns a tuple with the Timestamp field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimestamp

`func (o *AnalysisComment) SetTimestamp(v int64)`

SetTimestamp sets Timestamp field to given value.


### GetComment

`func (o *AnalysisComment) GetComment() string`

GetComment returns the Comment field if non-nil, zero value otherwise.

### GetCommentOk

`func (o *AnalysisComment) GetCommentOk() (*string, bool)`

GetCommentOk returns a tuple with the Comment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComment

`func (o *AnalysisComment) SetComment(v string)`

SetComment sets Comment field to given value.


### GetCommenter

`func (o *AnalysisComment) GetCommenter() string`

GetCommenter returns the Commenter field if non-nil, zero value otherwise.

### GetCommenterOk

`func (o *AnalysisComment) GetCommenterOk() (*string, bool)`

GetCommenterOk returns a tuple with the Commenter field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommenter

`func (o *AnalysisComment) SetCommenter(v string)`

SetCommenter sets Commenter field to given value.

### HasCommenter

`func (o *AnalysisComment) HasCommenter() bool`

HasCommenter returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


