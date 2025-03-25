# VexSubmitRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Project** | **string** |  | 
**ProjectName** | Pointer to **string** |  | [optional] 
**ProjectVersion** | Pointer to **string** |  | [optional] 
**Vex** | **string** |  | 

## Methods

### NewVexSubmitRequest

`func NewVexSubmitRequest(project string, vex string, ) *VexSubmitRequest`

NewVexSubmitRequest instantiates a new VexSubmitRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewVexSubmitRequestWithDefaults

`func NewVexSubmitRequestWithDefaults() *VexSubmitRequest`

NewVexSubmitRequestWithDefaults instantiates a new VexSubmitRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetProject

`func (o *VexSubmitRequest) GetProject() string`

GetProject returns the Project field if non-nil, zero value otherwise.

### GetProjectOk

`func (o *VexSubmitRequest) GetProjectOk() (*string, bool)`

GetProjectOk returns a tuple with the Project field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProject

`func (o *VexSubmitRequest) SetProject(v string)`

SetProject sets Project field to given value.


### GetProjectName

`func (o *VexSubmitRequest) GetProjectName() string`

GetProjectName returns the ProjectName field if non-nil, zero value otherwise.

### GetProjectNameOk

`func (o *VexSubmitRequest) GetProjectNameOk() (*string, bool)`

GetProjectNameOk returns a tuple with the ProjectName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProjectName

`func (o *VexSubmitRequest) SetProjectName(v string)`

SetProjectName sets ProjectName field to given value.

### HasProjectName

`func (o *VexSubmitRequest) HasProjectName() bool`

HasProjectName returns a boolean if a field has been set.

### GetProjectVersion

`func (o *VexSubmitRequest) GetProjectVersion() string`

GetProjectVersion returns the ProjectVersion field if non-nil, zero value otherwise.

### GetProjectVersionOk

`func (o *VexSubmitRequest) GetProjectVersionOk() (*string, bool)`

GetProjectVersionOk returns a tuple with the ProjectVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProjectVersion

`func (o *VexSubmitRequest) SetProjectVersion(v string)`

SetProjectVersion sets ProjectVersion field to given value.

### HasProjectVersion

`func (o *VexSubmitRequest) HasProjectVersion() bool`

HasProjectVersion returns a boolean if a field has been set.

### GetVex

`func (o *VexSubmitRequest) GetVex() string`

GetVex returns the Vex field if non-nil, zero value otherwise.

### GetVexOk

`func (o *VexSubmitRequest) GetVexOk() (*string, bool)`

GetVexOk returns a tuple with the Vex field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVex

`func (o *VexSubmitRequest) SetVex(v string)`

SetVex sets Vex field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


