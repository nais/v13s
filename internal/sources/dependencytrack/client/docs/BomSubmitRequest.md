# BomSubmitRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Project** | **string** |  | [readonly] 
**ProjectName** | Pointer to **string** |  | [optional] [readonly] 
**ProjectVersion** | Pointer to **string** |  | [optional] [readonly] 
**AutoCreate** | Pointer to **bool** |  | [optional] [readonly] 
**ParentUUID** | Pointer to **string** |  | [optional] [readonly] 
**ParentName** | Pointer to **string** |  | [optional] [readonly] 
**ParentVersion** | Pointer to **string** |  | [optional] [readonly] 
**Bom** | **string** | Base64 encoded BOM | [readonly] 

## Methods

### NewBomSubmitRequest

`func NewBomSubmitRequest(project string, bom string, ) *BomSubmitRequest`

NewBomSubmitRequest instantiates a new BomSubmitRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBomSubmitRequestWithDefaults

`func NewBomSubmitRequestWithDefaults() *BomSubmitRequest`

NewBomSubmitRequestWithDefaults instantiates a new BomSubmitRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetProject

`func (o *BomSubmitRequest) GetProject() string`

GetProject returns the Project field if non-nil, zero value otherwise.

### GetProjectOk

`func (o *BomSubmitRequest) GetProjectOk() (*string, bool)`

GetProjectOk returns a tuple with the Project field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProject

`func (o *BomSubmitRequest) SetProject(v string)`

SetProject sets Project field to given value.


### GetProjectName

`func (o *BomSubmitRequest) GetProjectName() string`

GetProjectName returns the ProjectName field if non-nil, zero value otherwise.

### GetProjectNameOk

`func (o *BomSubmitRequest) GetProjectNameOk() (*string, bool)`

GetProjectNameOk returns a tuple with the ProjectName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProjectName

`func (o *BomSubmitRequest) SetProjectName(v string)`

SetProjectName sets ProjectName field to given value.

### HasProjectName

`func (o *BomSubmitRequest) HasProjectName() bool`

HasProjectName returns a boolean if a field has been set.

### GetProjectVersion

`func (o *BomSubmitRequest) GetProjectVersion() string`

GetProjectVersion returns the ProjectVersion field if non-nil, zero value otherwise.

### GetProjectVersionOk

`func (o *BomSubmitRequest) GetProjectVersionOk() (*string, bool)`

GetProjectVersionOk returns a tuple with the ProjectVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProjectVersion

`func (o *BomSubmitRequest) SetProjectVersion(v string)`

SetProjectVersion sets ProjectVersion field to given value.

### HasProjectVersion

`func (o *BomSubmitRequest) HasProjectVersion() bool`

HasProjectVersion returns a boolean if a field has been set.

### GetAutoCreate

`func (o *BomSubmitRequest) GetAutoCreate() bool`

GetAutoCreate returns the AutoCreate field if non-nil, zero value otherwise.

### GetAutoCreateOk

`func (o *BomSubmitRequest) GetAutoCreateOk() (*bool, bool)`

GetAutoCreateOk returns a tuple with the AutoCreate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAutoCreate

`func (o *BomSubmitRequest) SetAutoCreate(v bool)`

SetAutoCreate sets AutoCreate field to given value.

### HasAutoCreate

`func (o *BomSubmitRequest) HasAutoCreate() bool`

HasAutoCreate returns a boolean if a field has been set.

### GetParentUUID

`func (o *BomSubmitRequest) GetParentUUID() string`

GetParentUUID returns the ParentUUID field if non-nil, zero value otherwise.

### GetParentUUIDOk

`func (o *BomSubmitRequest) GetParentUUIDOk() (*string, bool)`

GetParentUUIDOk returns a tuple with the ParentUUID field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetParentUUID

`func (o *BomSubmitRequest) SetParentUUID(v string)`

SetParentUUID sets ParentUUID field to given value.

### HasParentUUID

`func (o *BomSubmitRequest) HasParentUUID() bool`

HasParentUUID returns a boolean if a field has been set.

### GetParentName

`func (o *BomSubmitRequest) GetParentName() string`

GetParentName returns the ParentName field if non-nil, zero value otherwise.

### GetParentNameOk

`func (o *BomSubmitRequest) GetParentNameOk() (*string, bool)`

GetParentNameOk returns a tuple with the ParentName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetParentName

`func (o *BomSubmitRequest) SetParentName(v string)`

SetParentName sets ParentName field to given value.

### HasParentName

`func (o *BomSubmitRequest) HasParentName() bool`

HasParentName returns a boolean if a field has been set.

### GetParentVersion

`func (o *BomSubmitRequest) GetParentVersion() string`

GetParentVersion returns the ParentVersion field if non-nil, zero value otherwise.

### GetParentVersionOk

`func (o *BomSubmitRequest) GetParentVersionOk() (*string, bool)`

GetParentVersionOk returns a tuple with the ParentVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetParentVersion

`func (o *BomSubmitRequest) SetParentVersion(v string)`

SetParentVersion sets ParentVersion field to given value.

### HasParentVersion

`func (o *BomSubmitRequest) HasParentVersion() bool`

HasParentVersion returns a boolean if a field has been set.

### GetBom

`func (o *BomSubmitRequest) GetBom() string`

GetBom returns the Bom field if non-nil, zero value otherwise.

### GetBomOk

`func (o *BomSubmitRequest) GetBomOk() (*string, bool)`

GetBomOk returns a tuple with the Bom field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBom

`func (o *BomSubmitRequest) SetBom(v string)`

SetBom sets Bom field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


