# ApiKey

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Key** | **string** |  | 
**Comment** | Pointer to **string** |  | [optional] 
**Created** | Pointer to **time.Time** |  | [optional] 
**LastUsed** | Pointer to **time.Time** |  | [optional] 
**MaskedKey** | Pointer to **string** |  | [optional] 

## Methods

### NewApiKey

`func NewApiKey(key string, ) *ApiKey`

NewApiKey instantiates a new ApiKey object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewApiKeyWithDefaults

`func NewApiKeyWithDefaults() *ApiKey`

NewApiKeyWithDefaults instantiates a new ApiKey object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetKey

`func (o *ApiKey) GetKey() string`

GetKey returns the Key field if non-nil, zero value otherwise.

### GetKeyOk

`func (o *ApiKey) GetKeyOk() (*string, bool)`

GetKeyOk returns a tuple with the Key field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKey

`func (o *ApiKey) SetKey(v string)`

SetKey sets Key field to given value.


### GetComment

`func (o *ApiKey) GetComment() string`

GetComment returns the Comment field if non-nil, zero value otherwise.

### GetCommentOk

`func (o *ApiKey) GetCommentOk() (*string, bool)`

GetCommentOk returns a tuple with the Comment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComment

`func (o *ApiKey) SetComment(v string)`

SetComment sets Comment field to given value.

### HasComment

`func (o *ApiKey) HasComment() bool`

HasComment returns a boolean if a field has been set.

### GetCreated

`func (o *ApiKey) GetCreated() time.Time`

GetCreated returns the Created field if non-nil, zero value otherwise.

### GetCreatedOk

`func (o *ApiKey) GetCreatedOk() (*time.Time, bool)`

GetCreatedOk returns a tuple with the Created field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCreated

`func (o *ApiKey) SetCreated(v time.Time)`

SetCreated sets Created field to given value.

### HasCreated

`func (o *ApiKey) HasCreated() bool`

HasCreated returns a boolean if a field has been set.

### GetLastUsed

`func (o *ApiKey) GetLastUsed() time.Time`

GetLastUsed returns the LastUsed field if non-nil, zero value otherwise.

### GetLastUsedOk

`func (o *ApiKey) GetLastUsedOk() (*time.Time, bool)`

GetLastUsedOk returns a tuple with the LastUsed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastUsed

`func (o *ApiKey) SetLastUsed(v time.Time)`

SetLastUsed sets LastUsed field to given value.

### HasLastUsed

`func (o *ApiKey) HasLastUsed() bool`

HasLastUsed returns a boolean if a field has been set.

### GetMaskedKey

`func (o *ApiKey) GetMaskedKey() string`

GetMaskedKey returns the MaskedKey field if non-nil, zero value otherwise.

### GetMaskedKeyOk

`func (o *ApiKey) GetMaskedKeyOk() (*string, bool)`

GetMaskedKeyOk returns a tuple with the MaskedKey field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMaskedKey

`func (o *ApiKey) SetMaskedKey(v string)`

SetMaskedKey sets MaskedKey field to given value.

### HasMaskedKey

`func (o *ApiKey) HasMaskedKey() bool`

HasMaskedKey returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

