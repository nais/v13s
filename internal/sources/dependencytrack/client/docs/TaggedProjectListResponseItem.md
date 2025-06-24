# TaggedProjectListResponseItem

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Uuid** | **string** | UUID of the project | 
**Name** | **string** | Name of the project | 
**Version** | Pointer to **string** | Version of the project | [optional] 

## Methods

### NewTaggedProjectListResponseItem

`func NewTaggedProjectListResponseItem(uuid string, name string, ) *TaggedProjectListResponseItem`

NewTaggedProjectListResponseItem instantiates a new TaggedProjectListResponseItem object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewTaggedProjectListResponseItemWithDefaults

`func NewTaggedProjectListResponseItemWithDefaults() *TaggedProjectListResponseItem`

NewTaggedProjectListResponseItemWithDefaults instantiates a new TaggedProjectListResponseItem object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetUuid

`func (o *TaggedProjectListResponseItem) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *TaggedProjectListResponseItem) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *TaggedProjectListResponseItem) SetUuid(v string)`

SetUuid sets Uuid field to given value.


### GetName

`func (o *TaggedProjectListResponseItem) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *TaggedProjectListResponseItem) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *TaggedProjectListResponseItem) SetName(v string)`

SetName sets Name field to given value.


### GetVersion

`func (o *TaggedProjectListResponseItem) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *TaggedProjectListResponseItem) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *TaggedProjectListResponseItem) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *TaggedProjectListResponseItem) HasVersion() bool`

HasVersion returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


