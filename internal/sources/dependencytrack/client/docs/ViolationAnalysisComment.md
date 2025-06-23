# ViolationAnalysisComment

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Timestamp** | **int64** | UNIX epoch timestamp in milliseconds | 
**Comment** | **string** |  | 
**Commenter** | Pointer to **string** |  | [optional] 

## Methods

### NewViolationAnalysisComment

`func NewViolationAnalysisComment(timestamp int64, comment string, ) *ViolationAnalysisComment`

NewViolationAnalysisComment instantiates a new ViolationAnalysisComment object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewViolationAnalysisCommentWithDefaults

`func NewViolationAnalysisCommentWithDefaults() *ViolationAnalysisComment`

NewViolationAnalysisCommentWithDefaults instantiates a new ViolationAnalysisComment object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTimestamp

`func (o *ViolationAnalysisComment) GetTimestamp() int64`

GetTimestamp returns the Timestamp field if non-nil, zero value otherwise.

### GetTimestampOk

`func (o *ViolationAnalysisComment) GetTimestampOk() (*int64, bool)`

GetTimestampOk returns a tuple with the Timestamp field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimestamp

`func (o *ViolationAnalysisComment) SetTimestamp(v int64)`

SetTimestamp sets Timestamp field to given value.


### GetComment

`func (o *ViolationAnalysisComment) GetComment() string`

GetComment returns the Comment field if non-nil, zero value otherwise.

### GetCommentOk

`func (o *ViolationAnalysisComment) GetCommentOk() (*string, bool)`

GetCommentOk returns a tuple with the Comment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComment

`func (o *ViolationAnalysisComment) SetComment(v string)`

SetComment sets Comment field to given value.


### GetCommenter

`func (o *ViolationAnalysisComment) GetCommenter() string`

GetCommenter returns the Commenter field if non-nil, zero value otherwise.

### GetCommenterOk

`func (o *ViolationAnalysisComment) GetCommenterOk() (*string, bool)`

GetCommenterOk returns a tuple with the Commenter field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommenter

`func (o *ViolationAnalysisComment) SetCommenter(v string)`

SetCommenter sets Commenter field to given value.

### HasCommenter

`func (o *ViolationAnalysisComment) HasCommenter() bool`

HasCommenter returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


