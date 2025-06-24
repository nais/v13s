# CloneProjectRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Project** | **string** |  | 
**Version** | **string** |  | 
**IncludeTags** | Pointer to **bool** |  | [optional] 
**IncludeProperties** | Pointer to **bool** |  | [optional] 
**IncludeDependencies** | Pointer to **bool** |  | [optional] 
**IncludeComponents** | Pointer to **bool** |  | [optional] 
**IncludeServices** | Pointer to **bool** |  | [optional] 
**IncludeAuditHistory** | Pointer to **bool** |  | [optional] 
**IncludeACL** | Pointer to **bool** |  | [optional] 
**IncludePolicyViolations** | Pointer to **bool** |  | [optional] 
**MakeCloneLatest** | Pointer to **bool** |  | [optional] 

## Methods

### NewCloneProjectRequest

`func NewCloneProjectRequest(project string, version string, ) *CloneProjectRequest`

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


### GetIncludeTags

`func (o *CloneProjectRequest) GetIncludeTags() bool`

GetIncludeTags returns the IncludeTags field if non-nil, zero value otherwise.

### GetIncludeTagsOk

`func (o *CloneProjectRequest) GetIncludeTagsOk() (*bool, bool)`

GetIncludeTagsOk returns a tuple with the IncludeTags field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludeTags

`func (o *CloneProjectRequest) SetIncludeTags(v bool)`

SetIncludeTags sets IncludeTags field to given value.

### HasIncludeTags

`func (o *CloneProjectRequest) HasIncludeTags() bool`

HasIncludeTags returns a boolean if a field has been set.

### GetIncludeProperties

`func (o *CloneProjectRequest) GetIncludeProperties() bool`

GetIncludeProperties returns the IncludeProperties field if non-nil, zero value otherwise.

### GetIncludePropertiesOk

`func (o *CloneProjectRequest) GetIncludePropertiesOk() (*bool, bool)`

GetIncludePropertiesOk returns a tuple with the IncludeProperties field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludeProperties

`func (o *CloneProjectRequest) SetIncludeProperties(v bool)`

SetIncludeProperties sets IncludeProperties field to given value.

### HasIncludeProperties

`func (o *CloneProjectRequest) HasIncludeProperties() bool`

HasIncludeProperties returns a boolean if a field has been set.

### GetIncludeDependencies

`func (o *CloneProjectRequest) GetIncludeDependencies() bool`

GetIncludeDependencies returns the IncludeDependencies field if non-nil, zero value otherwise.

### GetIncludeDependenciesOk

`func (o *CloneProjectRequest) GetIncludeDependenciesOk() (*bool, bool)`

GetIncludeDependenciesOk returns a tuple with the IncludeDependencies field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludeDependencies

`func (o *CloneProjectRequest) SetIncludeDependencies(v bool)`

SetIncludeDependencies sets IncludeDependencies field to given value.

### HasIncludeDependencies

`func (o *CloneProjectRequest) HasIncludeDependencies() bool`

HasIncludeDependencies returns a boolean if a field has been set.

### GetIncludeComponents

`func (o *CloneProjectRequest) GetIncludeComponents() bool`

GetIncludeComponents returns the IncludeComponents field if non-nil, zero value otherwise.

### GetIncludeComponentsOk

`func (o *CloneProjectRequest) GetIncludeComponentsOk() (*bool, bool)`

GetIncludeComponentsOk returns a tuple with the IncludeComponents field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludeComponents

`func (o *CloneProjectRequest) SetIncludeComponents(v bool)`

SetIncludeComponents sets IncludeComponents field to given value.

### HasIncludeComponents

`func (o *CloneProjectRequest) HasIncludeComponents() bool`

HasIncludeComponents returns a boolean if a field has been set.

### GetIncludeServices

`func (o *CloneProjectRequest) GetIncludeServices() bool`

GetIncludeServices returns the IncludeServices field if non-nil, zero value otherwise.

### GetIncludeServicesOk

`func (o *CloneProjectRequest) GetIncludeServicesOk() (*bool, bool)`

GetIncludeServicesOk returns a tuple with the IncludeServices field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludeServices

`func (o *CloneProjectRequest) SetIncludeServices(v bool)`

SetIncludeServices sets IncludeServices field to given value.

### HasIncludeServices

`func (o *CloneProjectRequest) HasIncludeServices() bool`

HasIncludeServices returns a boolean if a field has been set.

### GetIncludeAuditHistory

`func (o *CloneProjectRequest) GetIncludeAuditHistory() bool`

GetIncludeAuditHistory returns the IncludeAuditHistory field if non-nil, zero value otherwise.

### GetIncludeAuditHistoryOk

`func (o *CloneProjectRequest) GetIncludeAuditHistoryOk() (*bool, bool)`

GetIncludeAuditHistoryOk returns a tuple with the IncludeAuditHistory field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludeAuditHistory

`func (o *CloneProjectRequest) SetIncludeAuditHistory(v bool)`

SetIncludeAuditHistory sets IncludeAuditHistory field to given value.

### HasIncludeAuditHistory

`func (o *CloneProjectRequest) HasIncludeAuditHistory() bool`

HasIncludeAuditHistory returns a boolean if a field has been set.

### GetIncludeACL

`func (o *CloneProjectRequest) GetIncludeACL() bool`

GetIncludeACL returns the IncludeACL field if non-nil, zero value otherwise.

### GetIncludeACLOk

`func (o *CloneProjectRequest) GetIncludeACLOk() (*bool, bool)`

GetIncludeACLOk returns a tuple with the IncludeACL field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludeACL

`func (o *CloneProjectRequest) SetIncludeACL(v bool)`

SetIncludeACL sets IncludeACL field to given value.

### HasIncludeACL

`func (o *CloneProjectRequest) HasIncludeACL() bool`

HasIncludeACL returns a boolean if a field has been set.

### GetIncludePolicyViolations

`func (o *CloneProjectRequest) GetIncludePolicyViolations() bool`

GetIncludePolicyViolations returns the IncludePolicyViolations field if non-nil, zero value otherwise.

### GetIncludePolicyViolationsOk

`func (o *CloneProjectRequest) GetIncludePolicyViolationsOk() (*bool, bool)`

GetIncludePolicyViolationsOk returns a tuple with the IncludePolicyViolations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludePolicyViolations

`func (o *CloneProjectRequest) SetIncludePolicyViolations(v bool)`

SetIncludePolicyViolations sets IncludePolicyViolations field to given value.

### HasIncludePolicyViolations

`func (o *CloneProjectRequest) HasIncludePolicyViolations() bool`

HasIncludePolicyViolations returns a boolean if a field has been set.

### GetMakeCloneLatest

`func (o *CloneProjectRequest) GetMakeCloneLatest() bool`

GetMakeCloneLatest returns the MakeCloneLatest field if non-nil, zero value otherwise.

### GetMakeCloneLatestOk

`func (o *CloneProjectRequest) GetMakeCloneLatestOk() (*bool, bool)`

GetMakeCloneLatestOk returns a tuple with the MakeCloneLatest field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMakeCloneLatest

`func (o *CloneProjectRequest) SetMakeCloneLatest(v bool)`

SetMakeCloneLatest sets MakeCloneLatest field to given value.

### HasMakeCloneLatest

`func (o *CloneProjectRequest) HasMakeCloneLatest() bool`

HasMakeCloneLatest returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


