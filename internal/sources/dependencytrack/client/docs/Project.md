# Project

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Authors** | Pointer to [**[]OrganizationalContact**](OrganizationalContact.md) |  | [optional] 
**Publisher** | Pointer to **string** |  | [optional] 
**Manufacturer** | Pointer to [**OrganizationalEntity**](OrganizationalEntity.md) |  | [optional] 
**Supplier** | Pointer to [**OrganizationalEntity**](OrganizationalEntity.md) |  | [optional] 
**Group** | Pointer to **string** |  | [optional] 
**Name** | Pointer to **string** |  | [optional] 
**Description** | Pointer to **string** |  | [optional] 
**Version** | Pointer to **string** |  | [optional] 
**Classifier** | Pointer to **string** |  | [optional] 
**CollectionLogic** | Pointer to **string** |  | [optional] 
**CollectionTag** | Pointer to [**Tag**](Tag.md) |  | [optional] 
**Cpe** | Pointer to **string** |  | [optional] 
**Purl** | Pointer to **string** |  | [optional] 
**SwidTagId** | Pointer to **string** |  | [optional] 
**DirectDependencies** | Pointer to **string** |  | [optional] 
**Uuid** | **string** |  | 
**Parent** | Pointer to [**Project**](Project.md) |  | [optional] 
**Children** | Pointer to [**[]Project**](Project.md) |  | [optional] 
**Properties** | Pointer to [**[]ProjectProperty**](ProjectProperty.md) |  | [optional] 
**Tags** | Pointer to [**[]Tag**](Tag.md) |  | [optional] 
**LastBomImport** | **int64** | UNIX epoch timestamp in milliseconds | 
**LastBomImportFormat** | Pointer to **string** |  | [optional] 
**LastInheritedRiskScore** | Pointer to **float64** |  | [optional] 
**LastVulnerabilityAnalysis** | Pointer to **int64** | UNIX epoch timestamp in milliseconds | [optional] 
**Active** | Pointer to **bool** |  | [optional] 
**IsLatest** | Pointer to **bool** |  | [optional] 
**AccessTeams** | Pointer to [**[]Team**](Team.md) |  | [optional] 
**ExternalReferences** | Pointer to [**[]ExternalReference**](ExternalReference.md) |  | [optional] 
**Metadata** | Pointer to [**ProjectMetadata**](ProjectMetadata.md) |  | [optional] 
**Versions** | Pointer to [**[]ProjectVersion**](ProjectVersion.md) |  | [optional] 
**Author** | Pointer to **string** |  | [optional] 
**Metrics** | Pointer to [**ProjectMetrics**](ProjectMetrics.md) |  | [optional] 
**BomRef** | Pointer to **string** |  | [optional] 

## Methods

### NewProject

`func NewProject(uuid string, lastBomImport int64, ) *Project`

NewProject instantiates a new Project object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewProjectWithDefaults

`func NewProjectWithDefaults() *Project`

NewProjectWithDefaults instantiates a new Project object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAuthors

`func (o *Project) GetAuthors() []OrganizationalContact`

GetAuthors returns the Authors field if non-nil, zero value otherwise.

### GetAuthorsOk

`func (o *Project) GetAuthorsOk() (*[]OrganizationalContact, bool)`

GetAuthorsOk returns a tuple with the Authors field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthors

`func (o *Project) SetAuthors(v []OrganizationalContact)`

SetAuthors sets Authors field to given value.

### HasAuthors

`func (o *Project) HasAuthors() bool`

HasAuthors returns a boolean if a field has been set.

### GetPublisher

`func (o *Project) GetPublisher() string`

GetPublisher returns the Publisher field if non-nil, zero value otherwise.

### GetPublisherOk

`func (o *Project) GetPublisherOk() (*string, bool)`

GetPublisherOk returns a tuple with the Publisher field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPublisher

`func (o *Project) SetPublisher(v string)`

SetPublisher sets Publisher field to given value.

### HasPublisher

`func (o *Project) HasPublisher() bool`

HasPublisher returns a boolean if a field has been set.

### GetManufacturer

`func (o *Project) GetManufacturer() OrganizationalEntity`

GetManufacturer returns the Manufacturer field if non-nil, zero value otherwise.

### GetManufacturerOk

`func (o *Project) GetManufacturerOk() (*OrganizationalEntity, bool)`

GetManufacturerOk returns a tuple with the Manufacturer field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetManufacturer

`func (o *Project) SetManufacturer(v OrganizationalEntity)`

SetManufacturer sets Manufacturer field to given value.

### HasManufacturer

`func (o *Project) HasManufacturer() bool`

HasManufacturer returns a boolean if a field has been set.

### GetSupplier

`func (o *Project) GetSupplier() OrganizationalEntity`

GetSupplier returns the Supplier field if non-nil, zero value otherwise.

### GetSupplierOk

`func (o *Project) GetSupplierOk() (*OrganizationalEntity, bool)`

GetSupplierOk returns a tuple with the Supplier field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSupplier

`func (o *Project) SetSupplier(v OrganizationalEntity)`

SetSupplier sets Supplier field to given value.

### HasSupplier

`func (o *Project) HasSupplier() bool`

HasSupplier returns a boolean if a field has been set.

### GetGroup

`func (o *Project) GetGroup() string`

GetGroup returns the Group field if non-nil, zero value otherwise.

### GetGroupOk

`func (o *Project) GetGroupOk() (*string, bool)`

GetGroupOk returns a tuple with the Group field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGroup

`func (o *Project) SetGroup(v string)`

SetGroup sets Group field to given value.

### HasGroup

`func (o *Project) HasGroup() bool`

HasGroup returns a boolean if a field has been set.

### GetName

`func (o *Project) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *Project) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *Project) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *Project) HasName() bool`

HasName returns a boolean if a field has been set.

### GetDescription

`func (o *Project) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *Project) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *Project) SetDescription(v string)`

SetDescription sets Description field to given value.

### HasDescription

`func (o *Project) HasDescription() bool`

HasDescription returns a boolean if a field has been set.

### GetVersion

`func (o *Project) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *Project) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *Project) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *Project) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### GetClassifier

`func (o *Project) GetClassifier() string`

GetClassifier returns the Classifier field if non-nil, zero value otherwise.

### GetClassifierOk

`func (o *Project) GetClassifierOk() (*string, bool)`

GetClassifierOk returns a tuple with the Classifier field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClassifier

`func (o *Project) SetClassifier(v string)`

SetClassifier sets Classifier field to given value.

### HasClassifier

`func (o *Project) HasClassifier() bool`

HasClassifier returns a boolean if a field has been set.

### GetCollectionLogic

`func (o *Project) GetCollectionLogic() string`

GetCollectionLogic returns the CollectionLogic field if non-nil, zero value otherwise.

### GetCollectionLogicOk

`func (o *Project) GetCollectionLogicOk() (*string, bool)`

GetCollectionLogicOk returns a tuple with the CollectionLogic field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCollectionLogic

`func (o *Project) SetCollectionLogic(v string)`

SetCollectionLogic sets CollectionLogic field to given value.

### HasCollectionLogic

`func (o *Project) HasCollectionLogic() bool`

HasCollectionLogic returns a boolean if a field has been set.

### GetCollectionTag

`func (o *Project) GetCollectionTag() Tag`

GetCollectionTag returns the CollectionTag field if non-nil, zero value otherwise.

### GetCollectionTagOk

`func (o *Project) GetCollectionTagOk() (*Tag, bool)`

GetCollectionTagOk returns a tuple with the CollectionTag field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCollectionTag

`func (o *Project) SetCollectionTag(v Tag)`

SetCollectionTag sets CollectionTag field to given value.

### HasCollectionTag

`func (o *Project) HasCollectionTag() bool`

HasCollectionTag returns a boolean if a field has been set.

### GetCpe

`func (o *Project) GetCpe() string`

GetCpe returns the Cpe field if non-nil, zero value otherwise.

### GetCpeOk

`func (o *Project) GetCpeOk() (*string, bool)`

GetCpeOk returns a tuple with the Cpe field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCpe

`func (o *Project) SetCpe(v string)`

SetCpe sets Cpe field to given value.

### HasCpe

`func (o *Project) HasCpe() bool`

HasCpe returns a boolean if a field has been set.

### GetPurl

`func (o *Project) GetPurl() string`

GetPurl returns the Purl field if non-nil, zero value otherwise.

### GetPurlOk

`func (o *Project) GetPurlOk() (*string, bool)`

GetPurlOk returns a tuple with the Purl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurl

`func (o *Project) SetPurl(v string)`

SetPurl sets Purl field to given value.

### HasPurl

`func (o *Project) HasPurl() bool`

HasPurl returns a boolean if a field has been set.

### GetSwidTagId

`func (o *Project) GetSwidTagId() string`

GetSwidTagId returns the SwidTagId field if non-nil, zero value otherwise.

### GetSwidTagIdOk

`func (o *Project) GetSwidTagIdOk() (*string, bool)`

GetSwidTagIdOk returns a tuple with the SwidTagId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSwidTagId

`func (o *Project) SetSwidTagId(v string)`

SetSwidTagId sets SwidTagId field to given value.

### HasSwidTagId

`func (o *Project) HasSwidTagId() bool`

HasSwidTagId returns a boolean if a field has been set.

### GetDirectDependencies

`func (o *Project) GetDirectDependencies() string`

GetDirectDependencies returns the DirectDependencies field if non-nil, zero value otherwise.

### GetDirectDependenciesOk

`func (o *Project) GetDirectDependenciesOk() (*string, bool)`

GetDirectDependenciesOk returns a tuple with the DirectDependencies field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDirectDependencies

`func (o *Project) SetDirectDependencies(v string)`

SetDirectDependencies sets DirectDependencies field to given value.

### HasDirectDependencies

`func (o *Project) HasDirectDependencies() bool`

HasDirectDependencies returns a boolean if a field has been set.

### GetUuid

`func (o *Project) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *Project) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *Project) SetUuid(v string)`

SetUuid sets Uuid field to given value.


### GetParent

`func (o *Project) GetParent() Project`

GetParent returns the Parent field if non-nil, zero value otherwise.

### GetParentOk

`func (o *Project) GetParentOk() (*Project, bool)`

GetParentOk returns a tuple with the Parent field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetParent

`func (o *Project) SetParent(v Project)`

SetParent sets Parent field to given value.

### HasParent

`func (o *Project) HasParent() bool`

HasParent returns a boolean if a field has been set.

### GetChildren

`func (o *Project) GetChildren() []Project`

GetChildren returns the Children field if non-nil, zero value otherwise.

### GetChildrenOk

`func (o *Project) GetChildrenOk() (*[]Project, bool)`

GetChildrenOk returns a tuple with the Children field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetChildren

`func (o *Project) SetChildren(v []Project)`

SetChildren sets Children field to given value.

### HasChildren

`func (o *Project) HasChildren() bool`

HasChildren returns a boolean if a field has been set.

### GetProperties

`func (o *Project) GetProperties() []ProjectProperty`

GetProperties returns the Properties field if non-nil, zero value otherwise.

### GetPropertiesOk

`func (o *Project) GetPropertiesOk() (*[]ProjectProperty, bool)`

GetPropertiesOk returns a tuple with the Properties field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProperties

`func (o *Project) SetProperties(v []ProjectProperty)`

SetProperties sets Properties field to given value.

### HasProperties

`func (o *Project) HasProperties() bool`

HasProperties returns a boolean if a field has been set.

### GetTags

`func (o *Project) GetTags() []Tag`

GetTags returns the Tags field if non-nil, zero value otherwise.

### GetTagsOk

`func (o *Project) GetTagsOk() (*[]Tag, bool)`

GetTagsOk returns a tuple with the Tags field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTags

`func (o *Project) SetTags(v []Tag)`

SetTags sets Tags field to given value.

### HasTags

`func (o *Project) HasTags() bool`

HasTags returns a boolean if a field has been set.

### GetLastBomImport

`func (o *Project) GetLastBomImport() int64`

GetLastBomImport returns the LastBomImport field if non-nil, zero value otherwise.

### GetLastBomImportOk

`func (o *Project) GetLastBomImportOk() (*int64, bool)`

GetLastBomImportOk returns a tuple with the LastBomImport field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastBomImport

`func (o *Project) SetLastBomImport(v int64)`

SetLastBomImport sets LastBomImport field to given value.


### GetLastBomImportFormat

`func (o *Project) GetLastBomImportFormat() string`

GetLastBomImportFormat returns the LastBomImportFormat field if non-nil, zero value otherwise.

### GetLastBomImportFormatOk

`func (o *Project) GetLastBomImportFormatOk() (*string, bool)`

GetLastBomImportFormatOk returns a tuple with the LastBomImportFormat field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastBomImportFormat

`func (o *Project) SetLastBomImportFormat(v string)`

SetLastBomImportFormat sets LastBomImportFormat field to given value.

### HasLastBomImportFormat

`func (o *Project) HasLastBomImportFormat() bool`

HasLastBomImportFormat returns a boolean if a field has been set.

### GetLastInheritedRiskScore

`func (o *Project) GetLastInheritedRiskScore() float64`

GetLastInheritedRiskScore returns the LastInheritedRiskScore field if non-nil, zero value otherwise.

### GetLastInheritedRiskScoreOk

`func (o *Project) GetLastInheritedRiskScoreOk() (*float64, bool)`

GetLastInheritedRiskScoreOk returns a tuple with the LastInheritedRiskScore field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastInheritedRiskScore

`func (o *Project) SetLastInheritedRiskScore(v float64)`

SetLastInheritedRiskScore sets LastInheritedRiskScore field to given value.

### HasLastInheritedRiskScore

`func (o *Project) HasLastInheritedRiskScore() bool`

HasLastInheritedRiskScore returns a boolean if a field has been set.

### GetLastVulnerabilityAnalysis

`func (o *Project) GetLastVulnerabilityAnalysis() int64`

GetLastVulnerabilityAnalysis returns the LastVulnerabilityAnalysis field if non-nil, zero value otherwise.

### GetLastVulnerabilityAnalysisOk

`func (o *Project) GetLastVulnerabilityAnalysisOk() (*int64, bool)`

GetLastVulnerabilityAnalysisOk returns a tuple with the LastVulnerabilityAnalysis field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastVulnerabilityAnalysis

`func (o *Project) SetLastVulnerabilityAnalysis(v int64)`

SetLastVulnerabilityAnalysis sets LastVulnerabilityAnalysis field to given value.

### HasLastVulnerabilityAnalysis

`func (o *Project) HasLastVulnerabilityAnalysis() bool`

HasLastVulnerabilityAnalysis returns a boolean if a field has been set.

### GetActive

`func (o *Project) GetActive() bool`

GetActive returns the Active field if non-nil, zero value otherwise.

### GetActiveOk

`func (o *Project) GetActiveOk() (*bool, bool)`

GetActiveOk returns a tuple with the Active field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActive

`func (o *Project) SetActive(v bool)`

SetActive sets Active field to given value.

### HasActive

`func (o *Project) HasActive() bool`

HasActive returns a boolean if a field has been set.

### GetIsLatest

`func (o *Project) GetIsLatest() bool`

GetIsLatest returns the IsLatest field if non-nil, zero value otherwise.

### GetIsLatestOk

`func (o *Project) GetIsLatestOk() (*bool, bool)`

GetIsLatestOk returns a tuple with the IsLatest field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsLatest

`func (o *Project) SetIsLatest(v bool)`

SetIsLatest sets IsLatest field to given value.

### HasIsLatest

`func (o *Project) HasIsLatest() bool`

HasIsLatest returns a boolean if a field has been set.

### GetAccessTeams

`func (o *Project) GetAccessTeams() []Team`

GetAccessTeams returns the AccessTeams field if non-nil, zero value otherwise.

### GetAccessTeamsOk

`func (o *Project) GetAccessTeamsOk() (*[]Team, bool)`

GetAccessTeamsOk returns a tuple with the AccessTeams field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAccessTeams

`func (o *Project) SetAccessTeams(v []Team)`

SetAccessTeams sets AccessTeams field to given value.

### HasAccessTeams

`func (o *Project) HasAccessTeams() bool`

HasAccessTeams returns a boolean if a field has been set.

### GetExternalReferences

`func (o *Project) GetExternalReferences() []ExternalReference`

GetExternalReferences returns the ExternalReferences field if non-nil, zero value otherwise.

### GetExternalReferencesOk

`func (o *Project) GetExternalReferencesOk() (*[]ExternalReference, bool)`

GetExternalReferencesOk returns a tuple with the ExternalReferences field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExternalReferences

`func (o *Project) SetExternalReferences(v []ExternalReference)`

SetExternalReferences sets ExternalReferences field to given value.

### HasExternalReferences

`func (o *Project) HasExternalReferences() bool`

HasExternalReferences returns a boolean if a field has been set.

### GetMetadata

`func (o *Project) GetMetadata() ProjectMetadata`

GetMetadata returns the Metadata field if non-nil, zero value otherwise.

### GetMetadataOk

`func (o *Project) GetMetadataOk() (*ProjectMetadata, bool)`

GetMetadataOk returns a tuple with the Metadata field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMetadata

`func (o *Project) SetMetadata(v ProjectMetadata)`

SetMetadata sets Metadata field to given value.

### HasMetadata

`func (o *Project) HasMetadata() bool`

HasMetadata returns a boolean if a field has been set.

### GetVersions

`func (o *Project) GetVersions() []ProjectVersion`

GetVersions returns the Versions field if non-nil, zero value otherwise.

### GetVersionsOk

`func (o *Project) GetVersionsOk() (*[]ProjectVersion, bool)`

GetVersionsOk returns a tuple with the Versions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersions

`func (o *Project) SetVersions(v []ProjectVersion)`

SetVersions sets Versions field to given value.

### HasVersions

`func (o *Project) HasVersions() bool`

HasVersions returns a boolean if a field has been set.

### GetAuthor

`func (o *Project) GetAuthor() string`

GetAuthor returns the Author field if non-nil, zero value otherwise.

### GetAuthorOk

`func (o *Project) GetAuthorOk() (*string, bool)`

GetAuthorOk returns a tuple with the Author field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthor

`func (o *Project) SetAuthor(v string)`

SetAuthor sets Author field to given value.

### HasAuthor

`func (o *Project) HasAuthor() bool`

HasAuthor returns a boolean if a field has been set.

### GetMetrics

`func (o *Project) GetMetrics() ProjectMetrics`

GetMetrics returns the Metrics field if non-nil, zero value otherwise.

### GetMetricsOk

`func (o *Project) GetMetricsOk() (*ProjectMetrics, bool)`

GetMetricsOk returns a tuple with the Metrics field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMetrics

`func (o *Project) SetMetrics(v ProjectMetrics)`

SetMetrics sets Metrics field to given value.

### HasMetrics

`func (o *Project) HasMetrics() bool`

HasMetrics returns a boolean if a field has been set.

### GetBomRef

`func (o *Project) GetBomRef() string`

GetBomRef returns the BomRef field if non-nil, zero value otherwise.

### GetBomRefOk

`func (o *Project) GetBomRefOk() (*string, bool)`

GetBomRefOk returns a tuple with the BomRef field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBomRef

`func (o *Project) SetBomRef(v string)`

SetBomRef sets BomRef field to given value.

### HasBomRef

`func (o *Project) HasBomRef() bool`

HasBomRef returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


