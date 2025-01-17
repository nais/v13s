# CloneProjectRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Project** | **string** |  | 
**Version** | Pointer to **string** |  | [optional] 

## Methods

### NewCloneProjectRequest

`func NewCloneProjectRequest(project string, ) *CloneProjectRequest`

NewCloneProjectRequest instantiates a new CloneProjectRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCloneProjectRequestWithDefaults

`func NewCloneProjectRequestWithDefaults() *CloneProjectRequest`

NewCloneProjectRequestWithDefaults instantiates a new CloneProjectRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetProject

`func (o *CloneProjectRequest) GetProject() string`

GetProject returns the Project field if non-nil, zero value otherwise.

### GetProjectOk

`func (o *CloneProjectRequest) GetProjectOk() (*string, bool)`

GetProjectOk returns a tuple with the Project field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProject

`func (o *CloneProjectRequest) SetProject(v string)`

SetProject sets Project field to given value.


### GetVersion

`func (o *CloneProjectRequest) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *CloneProjectRequest) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *CloneProjectRequest) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *CloneProjectRequest) HasVersion() bool`

HasVersion returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


