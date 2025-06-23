# RepositoryMetaComponent

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**RepositoryType** | **string** |  | 
**Namespace** | Pointer to **string** |  | [optional] 
**Name** | **string** |  | 
**LatestVersion** | **string** |  | 
**Published** | **int64** | UNIX epoch timestamp in milliseconds | 
**LastCheck** | **int64** | UNIX epoch timestamp in milliseconds | 

## Methods

### NewRepositoryMetaComponent

`func NewRepositoryMetaComponent(repositoryType string, name string, latestVersion string, published int64, lastCheck int64, ) *RepositoryMetaComponent`

NewRepositoryMetaComponent instantiates a new RepositoryMetaComponent object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewRepositoryMetaComponentWithDefaults

`func NewRepositoryMetaComponentWithDefaults() *RepositoryMetaComponent`

NewRepositoryMetaComponentWithDefaults instantiates a new RepositoryMetaComponent object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRepositoryType

`func (o *RepositoryMetaComponent) GetRepositoryType() string`

GetRepositoryType returns the RepositoryType field if non-nil, zero value otherwise.

### GetRepositoryTypeOk

`func (o *RepositoryMetaComponent) GetRepositoryTypeOk() (*string, bool)`

GetRepositoryTypeOk returns a tuple with the RepositoryType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRepositoryType

`func (o *RepositoryMetaComponent) SetRepositoryType(v string)`

SetRepositoryType sets RepositoryType field to given value.


### GetNamespace

`func (o *RepositoryMetaComponent) GetNamespace() string`

GetNamespace returns the Namespace field if non-nil, zero value otherwise.

### GetNamespaceOk

`func (o *RepositoryMetaComponent) GetNamespaceOk() (*string, bool)`

GetNamespaceOk returns a tuple with the Namespace field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNamespace

`func (o *RepositoryMetaComponent) SetNamespace(v string)`

SetNamespace sets Namespace field to given value.

### HasNamespace

`func (o *RepositoryMetaComponent) HasNamespace() bool`

HasNamespace returns a boolean if a field has been set.

### GetName

`func (o *RepositoryMetaComponent) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *RepositoryMetaComponent) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *RepositoryMetaComponent) SetName(v string)`

SetName sets Name field to given value.


### GetLatestVersion

`func (o *RepositoryMetaComponent) GetLatestVersion() string`

GetLatestVersion returns the LatestVersion field if non-nil, zero value otherwise.

### GetLatestVersionOk

`func (o *RepositoryMetaComponent) GetLatestVersionOk() (*string, bool)`

GetLatestVersionOk returns a tuple with the LatestVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLatestVersion

`func (o *RepositoryMetaComponent) SetLatestVersion(v string)`

SetLatestVersion sets LatestVersion field to given value.


### GetPublished

`func (o *RepositoryMetaComponent) GetPublished() int64`

GetPublished returns the Published field if non-nil, zero value otherwise.

### GetPublishedOk

`func (o *RepositoryMetaComponent) GetPublishedOk() (*int64, bool)`

GetPublishedOk returns a tuple with the Published field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPublished

`func (o *RepositoryMetaComponent) SetPublished(v int64)`

SetPublished sets Published field to given value.


### GetLastCheck

`func (o *RepositoryMetaComponent) GetLastCheck() int64`

GetLastCheck returns the LastCheck field if non-nil, zero value otherwise.

### GetLastCheckOk

`func (o *RepositoryMetaComponent) GetLastCheckOk() (*int64, bool)`

GetLastCheckOk returns a tuple with the LastCheck field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastCheck

`func (o *RepositoryMetaComponent) SetLastCheck(v int64)`

SetLastCheck sets LastCheck field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


