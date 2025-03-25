# ServiceComponent

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Provider** | Pointer to [**OrganizationalEntity**](OrganizationalEntity.md) |  | [optional] 
**Group** | Pointer to **string** |  | [optional] 
**Name** | Pointer to **string** |  | [optional] 
**Version** | Pointer to **string** |  | [optional] 
**Description** | Pointer to **string** |  | [optional] 
**Endpoints** | Pointer to **[]string** |  | [optional] 
**Authenticated** | Pointer to **bool** |  | [optional] 
**CrossesTrustBoundary** | Pointer to **bool** |  | [optional] 
**Data** | Pointer to [**[]DataClassification**](DataClassification.md) |  | [optional] 
**ExternalReferences** | Pointer to [**[]ExternalReference**](ExternalReference.md) |  | [optional] 
**Parent** | Pointer to [**ServiceComponent**](ServiceComponent.md) |  | [optional] 
**Children** | Pointer to [**[]ServiceComponent**](ServiceComponent.md) |  | [optional] 
**Vulnerabilities** | Pointer to [**[]Vulnerability**](Vulnerability.md) |  | [optional] 
**Project** | [**Project**](Project.md) |  | 
**LastInheritedRiskScore** | Pointer to **float64** |  | [optional] 
**Notes** | Pointer to **string** |  | [optional] 
**Uuid** | **string** |  | 
**BomRef** | Pointer to **string** |  | [optional] 

## Methods

### NewServiceComponent

`func NewServiceComponent(project Project, uuid string, ) *ServiceComponent`

NewServiceComponent instantiates a new ServiceComponent object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewServiceComponentWithDefaults

`func NewServiceComponentWithDefaults() *ServiceComponent`

NewServiceComponentWithDefaults instantiates a new ServiceComponent object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetProvider

`func (o *ServiceComponent) GetProvider() OrganizationalEntity`

GetProvider returns the Provider field if non-nil, zero value otherwise.

### GetProviderOk

`func (o *ServiceComponent) GetProviderOk() (*OrganizationalEntity, bool)`

GetProviderOk returns a tuple with the Provider field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProvider

`func (o *ServiceComponent) SetProvider(v OrganizationalEntity)`

SetProvider sets Provider field to given value.

### HasProvider

`func (o *ServiceComponent) HasProvider() bool`

HasProvider returns a boolean if a field has been set.

### GetGroup

`func (o *ServiceComponent) GetGroup() string`

GetGroup returns the Group field if non-nil, zero value otherwise.

### GetGroupOk

`func (o *ServiceComponent) GetGroupOk() (*string, bool)`

GetGroupOk returns a tuple with the Group field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGroup

`func (o *ServiceComponent) SetGroup(v string)`

SetGroup sets Group field to given value.

### HasGroup

`func (o *ServiceComponent) HasGroup() bool`

HasGroup returns a boolean if a field has been set.

### GetName

`func (o *ServiceComponent) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *ServiceComponent) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *ServiceComponent) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *ServiceComponent) HasName() bool`

HasName returns a boolean if a field has been set.

### GetVersion

`func (o *ServiceComponent) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *ServiceComponent) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *ServiceComponent) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *ServiceComponent) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### GetDescription

`func (o *ServiceComponent) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *ServiceComponent) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *ServiceComponent) SetDescription(v string)`

SetDescription sets Description field to given value.

### HasDescription

`func (o *ServiceComponent) HasDescription() bool`

HasDescription returns a boolean if a field has been set.

### GetEndpoints

`func (o *ServiceComponent) GetEndpoints() []string`

GetEndpoints returns the Endpoints field if non-nil, zero value otherwise.

### GetEndpointsOk

`func (o *ServiceComponent) GetEndpointsOk() (*[]string, bool)`

GetEndpointsOk returns a tuple with the Endpoints field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEndpoints

`func (o *ServiceComponent) SetEndpoints(v []string)`

SetEndpoints sets Endpoints field to given value.

### HasEndpoints

`func (o *ServiceComponent) HasEndpoints() bool`

HasEndpoints returns a boolean if a field has been set.

### GetAuthenticated

`func (o *ServiceComponent) GetAuthenticated() bool`

GetAuthenticated returns the Authenticated field if non-nil, zero value otherwise.

### GetAuthenticatedOk

`func (o *ServiceComponent) GetAuthenticatedOk() (*bool, bool)`

GetAuthenticatedOk returns a tuple with the Authenticated field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthenticated

`func (o *ServiceComponent) SetAuthenticated(v bool)`

SetAuthenticated sets Authenticated field to given value.

### HasAuthenticated

`func (o *ServiceComponent) HasAuthenticated() bool`

HasAuthenticated returns a boolean if a field has been set.

### GetCrossesTrustBoundary

`func (o *ServiceComponent) GetCrossesTrustBoundary() bool`

GetCrossesTrustBoundary returns the CrossesTrustBoundary field if non-nil, zero value otherwise.

### GetCrossesTrustBoundaryOk

`func (o *ServiceComponent) GetCrossesTrustBoundaryOk() (*bool, bool)`

GetCrossesTrustBoundaryOk returns a tuple with the CrossesTrustBoundary field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCrossesTrustBoundary

`func (o *ServiceComponent) SetCrossesTrustBoundary(v bool)`

SetCrossesTrustBoundary sets CrossesTrustBoundary field to given value.

### HasCrossesTrustBoundary

`func (o *ServiceComponent) HasCrossesTrustBoundary() bool`

HasCrossesTrustBoundary returns a boolean if a field has been set.

### GetData

`func (o *ServiceComponent) GetData() []DataClassification`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ServiceComponent) GetDataOk() (*[]DataClassification, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ServiceComponent) SetData(v []DataClassification)`

SetData sets Data field to given value.

### HasData

`func (o *ServiceComponent) HasData() bool`

HasData returns a boolean if a field has been set.

### GetExternalReferences

`func (o *ServiceComponent) GetExternalReferences() []ExternalReference`

GetExternalReferences returns the ExternalReferences field if non-nil, zero value otherwise.

### GetExternalReferencesOk

`func (o *ServiceComponent) GetExternalReferencesOk() (*[]ExternalReference, bool)`

GetExternalReferencesOk returns a tuple with the ExternalReferences field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExternalReferences

`func (o *ServiceComponent) SetExternalReferences(v []ExternalReference)`

SetExternalReferences sets ExternalReferences field to given value.

### HasExternalReferences

`func (o *ServiceComponent) HasExternalReferences() bool`

HasExternalReferences returns a boolean if a field has been set.

### GetParent

`func (o *ServiceComponent) GetParent() ServiceComponent`

GetParent returns the Parent field if non-nil, zero value otherwise.

### GetParentOk

`func (o *ServiceComponent) GetParentOk() (*ServiceComponent, bool)`

GetParentOk returns a tuple with the Parent field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetParent

`func (o *ServiceComponent) SetParent(v ServiceComponent)`

SetParent sets Parent field to given value.

### HasParent

`func (o *ServiceComponent) HasParent() bool`

HasParent returns a boolean if a field has been set.

### GetChildren

`func (o *ServiceComponent) GetChildren() []ServiceComponent`

GetChildren returns the Children field if non-nil, zero value otherwise.

### GetChildrenOk

`func (o *ServiceComponent) GetChildrenOk() (*[]ServiceComponent, bool)`

GetChildrenOk returns a tuple with the Children field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetChildren

`func (o *ServiceComponent) SetChildren(v []ServiceComponent)`

SetChildren sets Children field to given value.

### HasChildren

`func (o *ServiceComponent) HasChildren() bool`

HasChildren returns a boolean if a field has been set.

### GetVulnerabilities

`func (o *ServiceComponent) GetVulnerabilities() []Vulnerability`

GetVulnerabilities returns the Vulnerabilities field if non-nil, zero value otherwise.

### GetVulnerabilitiesOk

`func (o *ServiceComponent) GetVulnerabilitiesOk() (*[]Vulnerability, bool)`

GetVulnerabilitiesOk returns a tuple with the Vulnerabilities field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerabilities

`func (o *ServiceComponent) SetVulnerabilities(v []Vulnerability)`

SetVulnerabilities sets Vulnerabilities field to given value.

### HasVulnerabilities

`func (o *ServiceComponent) HasVulnerabilities() bool`

HasVulnerabilities returns a boolean if a field has been set.

### GetProject

`func (o *ServiceComponent) GetProject() Project`

GetProject returns the Project field if non-nil, zero value otherwise.

### GetProjectOk

`func (o *ServiceComponent) GetProjectOk() (*Project, bool)`

GetProjectOk returns a tuple with the Project field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProject

`func (o *ServiceComponent) SetProject(v Project)`

SetProject sets Project field to given value.


### GetLastInheritedRiskScore

`func (o *ServiceComponent) GetLastInheritedRiskScore() float64`

GetLastInheritedRiskScore returns the LastInheritedRiskScore field if non-nil, zero value otherwise.

### GetLastInheritedRiskScoreOk

`func (o *ServiceComponent) GetLastInheritedRiskScoreOk() (*float64, bool)`

GetLastInheritedRiskScoreOk returns a tuple with the LastInheritedRiskScore field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastInheritedRiskScore

`func (o *ServiceComponent) SetLastInheritedRiskScore(v float64)`

SetLastInheritedRiskScore sets LastInheritedRiskScore field to given value.

### HasLastInheritedRiskScore

`func (o *ServiceComponent) HasLastInheritedRiskScore() bool`

HasLastInheritedRiskScore returns a boolean if a field has been set.

### GetNotes

`func (o *ServiceComponent) GetNotes() string`

GetNotes returns the Notes field if non-nil, zero value otherwise.

### GetNotesOk

`func (o *ServiceComponent) GetNotesOk() (*string, bool)`

GetNotesOk returns a tuple with the Notes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNotes

`func (o *ServiceComponent) SetNotes(v string)`

SetNotes sets Notes field to given value.

### HasNotes

`func (o *ServiceComponent) HasNotes() bool`

HasNotes returns a boolean if a field has been set.

### GetUuid

`func (o *ServiceComponent) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *ServiceComponent) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *ServiceComponent) SetUuid(v string)`

SetUuid sets Uuid field to given value.


### GetBomRef

`func (o *ServiceComponent) GetBomRef() string`

GetBomRef returns the BomRef field if non-nil, zero value otherwise.

### GetBomRefOk

`func (o *ServiceComponent) GetBomRefOk() (*string, bool)`

GetBomRefOk returns a tuple with the BomRef field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBomRef

`func (o *ServiceComponent) SetBomRef(v string)`

SetBomRef sets BomRef field to given value.

### HasBomRef

`func (o *ServiceComponent) HasBomRef() bool`

HasBomRef returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


