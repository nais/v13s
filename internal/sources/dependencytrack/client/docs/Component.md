# Component

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Authors** | Pointer to [**[]OrganizationalContact**](OrganizationalContact.md) |  | [optional] 
**Publisher** | Pointer to **string** |  | [optional] 
**Supplier** | Pointer to [**OrganizationalEntity**](OrganizationalEntity.md) |  | [optional] 
**Group** | Pointer to **string** |  | [optional] 
**Name** | Pointer to **string** |  | [optional] 
**Version** | Pointer to **string** |  | [optional] 
**Classifier** | **string** |  | 
**Filename** | Pointer to **string** |  | [optional] 
**Extension** | Pointer to **string** |  | [optional] 
**Md5** | Pointer to **string** |  | [optional] 
**Sha1** | Pointer to **string** |  | [optional] 
**Sha256** | Pointer to **string** |  | [optional] 
**Sha384** | Pointer to **string** |  | [optional] 
**Sha512** | Pointer to **string** |  | [optional] 
**Sha3256** | Pointer to **string** |  | [optional] 
**Sha3384** | Pointer to **string** |  | [optional] 
**Sha3512** | Pointer to **string** |  | [optional] 
**Blake2b256** | Pointer to **string** |  | [optional] 
**Blake2b384** | Pointer to **string** |  | [optional] 
**Blake2b512** | Pointer to **string** |  | [optional] 
**Blake3** | Pointer to **string** |  | [optional] 
**Cpe** | Pointer to **string** |  | [optional] 
**Purl** | Pointer to **string** |  | [optional] 
**PurlCoordinates** | Pointer to **string** |  | [optional] [readonly] 
**SwidTagId** | Pointer to **string** |  | [optional] 
**Description** | Pointer to **string** |  | [optional] 
**Copyright** | Pointer to **string** |  | [optional] 
**License** | Pointer to **string** |  | [optional] 
**LicenseExpression** | Pointer to **string** |  | [optional] 
**LicenseUrl** | Pointer to **string** |  | [optional] 
**ResolvedLicense** | Pointer to [**License**](License.md) |  | [optional] 
**DirectDependencies** | Pointer to **string** |  | [optional] 
**ExternalReferences** | Pointer to [**[]ExternalReference**](ExternalReference.md) |  | [optional] 
**Parent** | Pointer to [**Component**](Component.md) |  | [optional] 
**Children** | Pointer to [**[]Component**](Component.md) |  | [optional] 
**Properties** | Pointer to [**[]ComponentProperty**](ComponentProperty.md) |  | [optional] 
**Vulnerabilities** | Pointer to [**[]Vulnerability**](Vulnerability.md) |  | [optional] 
**Project** | [**Project**](Project.md) |  | 
**LastInheritedRiskScore** | Pointer to **float64** |  | [optional] 
**Notes** | Pointer to **string** |  | [optional] 
**Uuid** | **string** |  | 
**Author** | Pointer to **string** |  | [optional] 
**Metrics** | Pointer to [**DependencyMetrics**](DependencyMetrics.md) |  | [optional] 
**RepositoryMeta** | Pointer to [**RepositoryMetaComponent**](RepositoryMetaComponent.md) |  | [optional] 
**DependencyGraph** | Pointer to **[]string** |  | [optional] 
**ExpandDependencyGraph** | Pointer to **bool** |  | [optional] 
**IsInternal** | Pointer to **bool** |  | [optional] 

## Methods

### NewComponent

`func NewComponent(classifier string, project Project, uuid string, ) *Component`

NewComponent instantiates a new Component object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewComponentWithDefaults

`func NewComponentWithDefaults() *Component`

NewComponentWithDefaults instantiates a new Component object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetAuthors

`func (o *Component) GetAuthors() []OrganizationalContact`

GetAuthors returns the Authors field if non-nil, zero value otherwise.

### GetAuthorsOk

`func (o *Component) GetAuthorsOk() (*[]OrganizationalContact, bool)`

GetAuthorsOk returns a tuple with the Authors field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthors

`func (o *Component) SetAuthors(v []OrganizationalContact)`

SetAuthors sets Authors field to given value.

### HasAuthors

`func (o *Component) HasAuthors() bool`

HasAuthors returns a boolean if a field has been set.

### GetPublisher

`func (o *Component) GetPublisher() string`

GetPublisher returns the Publisher field if non-nil, zero value otherwise.

### GetPublisherOk

`func (o *Component) GetPublisherOk() (*string, bool)`

GetPublisherOk returns a tuple with the Publisher field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPublisher

`func (o *Component) SetPublisher(v string)`

SetPublisher sets Publisher field to given value.

### HasPublisher

`func (o *Component) HasPublisher() bool`

HasPublisher returns a boolean if a field has been set.

### GetSupplier

`func (o *Component) GetSupplier() OrganizationalEntity`

GetSupplier returns the Supplier field if non-nil, zero value otherwise.

### GetSupplierOk

`func (o *Component) GetSupplierOk() (*OrganizationalEntity, bool)`

GetSupplierOk returns a tuple with the Supplier field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSupplier

`func (o *Component) SetSupplier(v OrganizationalEntity)`

SetSupplier sets Supplier field to given value.

### HasSupplier

`func (o *Component) HasSupplier() bool`

HasSupplier returns a boolean if a field has been set.

### GetGroup

`func (o *Component) GetGroup() string`

GetGroup returns the Group field if non-nil, zero value otherwise.

### GetGroupOk

`func (o *Component) GetGroupOk() (*string, bool)`

GetGroupOk returns a tuple with the Group field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGroup

`func (o *Component) SetGroup(v string)`

SetGroup sets Group field to given value.

### HasGroup

`func (o *Component) HasGroup() bool`

HasGroup returns a boolean if a field has been set.

### GetName

`func (o *Component) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *Component) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *Component) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *Component) HasName() bool`

HasName returns a boolean if a field has been set.

### GetVersion

`func (o *Component) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *Component) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *Component) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *Component) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### GetClassifier

`func (o *Component) GetClassifier() string`

GetClassifier returns the Classifier field if non-nil, zero value otherwise.

### GetClassifierOk

`func (o *Component) GetClassifierOk() (*string, bool)`

GetClassifierOk returns a tuple with the Classifier field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClassifier

`func (o *Component) SetClassifier(v string)`

SetClassifier sets Classifier field to given value.


### GetFilename

`func (o *Component) GetFilename() string`

GetFilename returns the Filename field if non-nil, zero value otherwise.

### GetFilenameOk

`func (o *Component) GetFilenameOk() (*string, bool)`

GetFilenameOk returns a tuple with the Filename field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFilename

`func (o *Component) SetFilename(v string)`

SetFilename sets Filename field to given value.

### HasFilename

`func (o *Component) HasFilename() bool`

HasFilename returns a boolean if a field has been set.

### GetExtension

`func (o *Component) GetExtension() string`

GetExtension returns the Extension field if non-nil, zero value otherwise.

### GetExtensionOk

`func (o *Component) GetExtensionOk() (*string, bool)`

GetExtensionOk returns a tuple with the Extension field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExtension

`func (o *Component) SetExtension(v string)`

SetExtension sets Extension field to given value.

### HasExtension

`func (o *Component) HasExtension() bool`

HasExtension returns a boolean if a field has been set.

### GetMd5

`func (o *Component) GetMd5() string`

GetMd5 returns the Md5 field if non-nil, zero value otherwise.

### GetMd5Ok

`func (o *Component) GetMd5Ok() (*string, bool)`

GetMd5Ok returns a tuple with the Md5 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMd5

`func (o *Component) SetMd5(v string)`

SetMd5 sets Md5 field to given value.

### HasMd5

`func (o *Component) HasMd5() bool`

HasMd5 returns a boolean if a field has been set.

### GetSha1

`func (o *Component) GetSha1() string`

GetSha1 returns the Sha1 field if non-nil, zero value otherwise.

### GetSha1Ok

`func (o *Component) GetSha1Ok() (*string, bool)`

GetSha1Ok returns a tuple with the Sha1 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSha1

`func (o *Component) SetSha1(v string)`

SetSha1 sets Sha1 field to given value.

### HasSha1

`func (o *Component) HasSha1() bool`

HasSha1 returns a boolean if a field has been set.

### GetSha256

`func (o *Component) GetSha256() string`

GetSha256 returns the Sha256 field if non-nil, zero value otherwise.

### GetSha256Ok

`func (o *Component) GetSha256Ok() (*string, bool)`

GetSha256Ok returns a tuple with the Sha256 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSha256

`func (o *Component) SetSha256(v string)`

SetSha256 sets Sha256 field to given value.

### HasSha256

`func (o *Component) HasSha256() bool`

HasSha256 returns a boolean if a field has been set.

### GetSha384

`func (o *Component) GetSha384() string`

GetSha384 returns the Sha384 field if non-nil, zero value otherwise.

### GetSha384Ok

`func (o *Component) GetSha384Ok() (*string, bool)`

GetSha384Ok returns a tuple with the Sha384 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSha384

`func (o *Component) SetSha384(v string)`

SetSha384 sets Sha384 field to given value.

### HasSha384

`func (o *Component) HasSha384() bool`

HasSha384 returns a boolean if a field has been set.

### GetSha512

`func (o *Component) GetSha512() string`

GetSha512 returns the Sha512 field if non-nil, zero value otherwise.

### GetSha512Ok

`func (o *Component) GetSha512Ok() (*string, bool)`

GetSha512Ok returns a tuple with the Sha512 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSha512

`func (o *Component) SetSha512(v string)`

SetSha512 sets Sha512 field to given value.

### HasSha512

`func (o *Component) HasSha512() bool`

HasSha512 returns a boolean if a field has been set.

### GetSha3256

`func (o *Component) GetSha3256() string`

GetSha3256 returns the Sha3256 field if non-nil, zero value otherwise.

### GetSha3256Ok

`func (o *Component) GetSha3256Ok() (*string, bool)`

GetSha3256Ok returns a tuple with the Sha3256 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSha3256

`func (o *Component) SetSha3256(v string)`

SetSha3256 sets Sha3256 field to given value.

### HasSha3256

`func (o *Component) HasSha3256() bool`

HasSha3256 returns a boolean if a field has been set.

### GetSha3384

`func (o *Component) GetSha3384() string`

GetSha3384 returns the Sha3384 field if non-nil, zero value otherwise.

### GetSha3384Ok

`func (o *Component) GetSha3384Ok() (*string, bool)`

GetSha3384Ok returns a tuple with the Sha3384 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSha3384

`func (o *Component) SetSha3384(v string)`

SetSha3384 sets Sha3384 field to given value.

### HasSha3384

`func (o *Component) HasSha3384() bool`

HasSha3384 returns a boolean if a field has been set.

### GetSha3512

`func (o *Component) GetSha3512() string`

GetSha3512 returns the Sha3512 field if non-nil, zero value otherwise.

### GetSha3512Ok

`func (o *Component) GetSha3512Ok() (*string, bool)`

GetSha3512Ok returns a tuple with the Sha3512 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSha3512

`func (o *Component) SetSha3512(v string)`

SetSha3512 sets Sha3512 field to given value.

### HasSha3512

`func (o *Component) HasSha3512() bool`

HasSha3512 returns a boolean if a field has been set.

### GetBlake2b256

`func (o *Component) GetBlake2b256() string`

GetBlake2b256 returns the Blake2b256 field if non-nil, zero value otherwise.

### GetBlake2b256Ok

`func (o *Component) GetBlake2b256Ok() (*string, bool)`

GetBlake2b256Ok returns a tuple with the Blake2b256 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBlake2b256

`func (o *Component) SetBlake2b256(v string)`

SetBlake2b256 sets Blake2b256 field to given value.

### HasBlake2b256

`func (o *Component) HasBlake2b256() bool`

HasBlake2b256 returns a boolean if a field has been set.

### GetBlake2b384

`func (o *Component) GetBlake2b384() string`

GetBlake2b384 returns the Blake2b384 field if non-nil, zero value otherwise.

### GetBlake2b384Ok

`func (o *Component) GetBlake2b384Ok() (*string, bool)`

GetBlake2b384Ok returns a tuple with the Blake2b384 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBlake2b384

`func (o *Component) SetBlake2b384(v string)`

SetBlake2b384 sets Blake2b384 field to given value.

### HasBlake2b384

`func (o *Component) HasBlake2b384() bool`

HasBlake2b384 returns a boolean if a field has been set.

### GetBlake2b512

`func (o *Component) GetBlake2b512() string`

GetBlake2b512 returns the Blake2b512 field if non-nil, zero value otherwise.

### GetBlake2b512Ok

`func (o *Component) GetBlake2b512Ok() (*string, bool)`

GetBlake2b512Ok returns a tuple with the Blake2b512 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBlake2b512

`func (o *Component) SetBlake2b512(v string)`

SetBlake2b512 sets Blake2b512 field to given value.

### HasBlake2b512

`func (o *Component) HasBlake2b512() bool`

HasBlake2b512 returns a boolean if a field has been set.

### GetBlake3

`func (o *Component) GetBlake3() string`

GetBlake3 returns the Blake3 field if non-nil, zero value otherwise.

### GetBlake3Ok

`func (o *Component) GetBlake3Ok() (*string, bool)`

GetBlake3Ok returns a tuple with the Blake3 field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBlake3

`func (o *Component) SetBlake3(v string)`

SetBlake3 sets Blake3 field to given value.

### HasBlake3

`func (o *Component) HasBlake3() bool`

HasBlake3 returns a boolean if a field has been set.

### GetCpe

`func (o *Component) GetCpe() string`

GetCpe returns the Cpe field if non-nil, zero value otherwise.

### GetCpeOk

`func (o *Component) GetCpeOk() (*string, bool)`

GetCpeOk returns a tuple with the Cpe field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCpe

`func (o *Component) SetCpe(v string)`

SetCpe sets Cpe field to given value.

### HasCpe

`func (o *Component) HasCpe() bool`

HasCpe returns a boolean if a field has been set.

### GetPurl

`func (o *Component) GetPurl() string`

GetPurl returns the Purl field if non-nil, zero value otherwise.

### GetPurlOk

`func (o *Component) GetPurlOk() (*string, bool)`

GetPurlOk returns a tuple with the Purl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurl

`func (o *Component) SetPurl(v string)`

SetPurl sets Purl field to given value.

### HasPurl

`func (o *Component) HasPurl() bool`

HasPurl returns a boolean if a field has been set.

### GetPurlCoordinates

`func (o *Component) GetPurlCoordinates() string`

GetPurlCoordinates returns the PurlCoordinates field if non-nil, zero value otherwise.

### GetPurlCoordinatesOk

`func (o *Component) GetPurlCoordinatesOk() (*string, bool)`

GetPurlCoordinatesOk returns a tuple with the PurlCoordinates field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurlCoordinates

`func (o *Component) SetPurlCoordinates(v string)`

SetPurlCoordinates sets PurlCoordinates field to given value.

### HasPurlCoordinates

`func (o *Component) HasPurlCoordinates() bool`

HasPurlCoordinates returns a boolean if a field has been set.

### GetSwidTagId

`func (o *Component) GetSwidTagId() string`

GetSwidTagId returns the SwidTagId field if non-nil, zero value otherwise.

### GetSwidTagIdOk

`func (o *Component) GetSwidTagIdOk() (*string, bool)`

GetSwidTagIdOk returns a tuple with the SwidTagId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSwidTagId

`func (o *Component) SetSwidTagId(v string)`

SetSwidTagId sets SwidTagId field to given value.

### HasSwidTagId

`func (o *Component) HasSwidTagId() bool`

HasSwidTagId returns a boolean if a field has been set.

### GetDescription

`func (o *Component) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *Component) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *Component) SetDescription(v string)`

SetDescription sets Description field to given value.

### HasDescription

`func (o *Component) HasDescription() bool`

HasDescription returns a boolean if a field has been set.

### GetCopyright

`func (o *Component) GetCopyright() string`

GetCopyright returns the Copyright field if non-nil, zero value otherwise.

### GetCopyrightOk

`func (o *Component) GetCopyrightOk() (*string, bool)`

GetCopyrightOk returns a tuple with the Copyright field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCopyright

`func (o *Component) SetCopyright(v string)`

SetCopyright sets Copyright field to given value.

### HasCopyright

`func (o *Component) HasCopyright() bool`

HasCopyright returns a boolean if a field has been set.

### GetLicense

`func (o *Component) GetLicense() string`

GetLicense returns the License field if non-nil, zero value otherwise.

### GetLicenseOk

`func (o *Component) GetLicenseOk() (*string, bool)`

GetLicenseOk returns a tuple with the License field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLicense

`func (o *Component) SetLicense(v string)`

SetLicense sets License field to given value.

### HasLicense

`func (o *Component) HasLicense() bool`

HasLicense returns a boolean if a field has been set.

### GetLicenseExpression

`func (o *Component) GetLicenseExpression() string`

GetLicenseExpression returns the LicenseExpression field if non-nil, zero value otherwise.

### GetLicenseExpressionOk

`func (o *Component) GetLicenseExpressionOk() (*string, bool)`

GetLicenseExpressionOk returns a tuple with the LicenseExpression field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLicenseExpression

`func (o *Component) SetLicenseExpression(v string)`

SetLicenseExpression sets LicenseExpression field to given value.

### HasLicenseExpression

`func (o *Component) HasLicenseExpression() bool`

HasLicenseExpression returns a boolean if a field has been set.

### GetLicenseUrl

`func (o *Component) GetLicenseUrl() string`

GetLicenseUrl returns the LicenseUrl field if non-nil, zero value otherwise.

### GetLicenseUrlOk

`func (o *Component) GetLicenseUrlOk() (*string, bool)`

GetLicenseUrlOk returns a tuple with the LicenseUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLicenseUrl

`func (o *Component) SetLicenseUrl(v string)`

SetLicenseUrl sets LicenseUrl field to given value.

### HasLicenseUrl

`func (o *Component) HasLicenseUrl() bool`

HasLicenseUrl returns a boolean if a field has been set.

### GetResolvedLicense

`func (o *Component) GetResolvedLicense() License`

GetResolvedLicense returns the ResolvedLicense field if non-nil, zero value otherwise.

### GetResolvedLicenseOk

`func (o *Component) GetResolvedLicenseOk() (*License, bool)`

GetResolvedLicenseOk returns a tuple with the ResolvedLicense field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetResolvedLicense

`func (o *Component) SetResolvedLicense(v License)`

SetResolvedLicense sets ResolvedLicense field to given value.

### HasResolvedLicense

`func (o *Component) HasResolvedLicense() bool`

HasResolvedLicense returns a boolean if a field has been set.

### GetDirectDependencies

`func (o *Component) GetDirectDependencies() string`

GetDirectDependencies returns the DirectDependencies field if non-nil, zero value otherwise.

### GetDirectDependenciesOk

`func (o *Component) GetDirectDependenciesOk() (*string, bool)`

GetDirectDependenciesOk returns a tuple with the DirectDependencies field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDirectDependencies

`func (o *Component) SetDirectDependencies(v string)`

SetDirectDependencies sets DirectDependencies field to given value.

### HasDirectDependencies

`func (o *Component) HasDirectDependencies() bool`

HasDirectDependencies returns a boolean if a field has been set.

### GetExternalReferences

`func (o *Component) GetExternalReferences() []ExternalReference`

GetExternalReferences returns the ExternalReferences field if non-nil, zero value otherwise.

### GetExternalReferencesOk

`func (o *Component) GetExternalReferencesOk() (*[]ExternalReference, bool)`

GetExternalReferencesOk returns a tuple with the ExternalReferences field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExternalReferences

`func (o *Component) SetExternalReferences(v []ExternalReference)`

SetExternalReferences sets ExternalReferences field to given value.

### HasExternalReferences

`func (o *Component) HasExternalReferences() bool`

HasExternalReferences returns a boolean if a field has been set.

### GetParent

`func (o *Component) GetParent() Component`

GetParent returns the Parent field if non-nil, zero value otherwise.

### GetParentOk

`func (o *Component) GetParentOk() (*Component, bool)`

GetParentOk returns a tuple with the Parent field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetParent

`func (o *Component) SetParent(v Component)`

SetParent sets Parent field to given value.

### HasParent

`func (o *Component) HasParent() bool`

HasParent returns a boolean if a field has been set.

### GetChildren

`func (o *Component) GetChildren() []Component`

GetChildren returns the Children field if non-nil, zero value otherwise.

### GetChildrenOk

`func (o *Component) GetChildrenOk() (*[]Component, bool)`

GetChildrenOk returns a tuple with the Children field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetChildren

`func (o *Component) SetChildren(v []Component)`

SetChildren sets Children field to given value.

### HasChildren

`func (o *Component) HasChildren() bool`

HasChildren returns a boolean if a field has been set.

### GetProperties

`func (o *Component) GetProperties() []ComponentProperty`

GetProperties returns the Properties field if non-nil, zero value otherwise.

### GetPropertiesOk

`func (o *Component) GetPropertiesOk() (*[]ComponentProperty, bool)`

GetPropertiesOk returns a tuple with the Properties field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProperties

`func (o *Component) SetProperties(v []ComponentProperty)`

SetProperties sets Properties field to given value.

### HasProperties

`func (o *Component) HasProperties() bool`

HasProperties returns a boolean if a field has been set.

### GetVulnerabilities

`func (o *Component) GetVulnerabilities() []Vulnerability`

GetVulnerabilities returns the Vulnerabilities field if non-nil, zero value otherwise.

### GetVulnerabilitiesOk

`func (o *Component) GetVulnerabilitiesOk() (*[]Vulnerability, bool)`

GetVulnerabilitiesOk returns a tuple with the Vulnerabilities field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerabilities

`func (o *Component) SetVulnerabilities(v []Vulnerability)`

SetVulnerabilities sets Vulnerabilities field to given value.

### HasVulnerabilities

`func (o *Component) HasVulnerabilities() bool`

HasVulnerabilities returns a boolean if a field has been set.

### GetProject

`func (o *Component) GetProject() Project`

GetProject returns the Project field if non-nil, zero value otherwise.

### GetProjectOk

`func (o *Component) GetProjectOk() (*Project, bool)`

GetProjectOk returns a tuple with the Project field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProject

`func (o *Component) SetProject(v Project)`

SetProject sets Project field to given value.


### GetLastInheritedRiskScore

`func (o *Component) GetLastInheritedRiskScore() float64`

GetLastInheritedRiskScore returns the LastInheritedRiskScore field if non-nil, zero value otherwise.

### GetLastInheritedRiskScoreOk

`func (o *Component) GetLastInheritedRiskScoreOk() (*float64, bool)`

GetLastInheritedRiskScoreOk returns a tuple with the LastInheritedRiskScore field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastInheritedRiskScore

`func (o *Component) SetLastInheritedRiskScore(v float64)`

SetLastInheritedRiskScore sets LastInheritedRiskScore field to given value.

### HasLastInheritedRiskScore

`func (o *Component) HasLastInheritedRiskScore() bool`

HasLastInheritedRiskScore returns a boolean if a field has been set.

### GetNotes

`func (o *Component) GetNotes() string`

GetNotes returns the Notes field if non-nil, zero value otherwise.

### GetNotesOk

`func (o *Component) GetNotesOk() (*string, bool)`

GetNotesOk returns a tuple with the Notes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNotes

`func (o *Component) SetNotes(v string)`

SetNotes sets Notes field to given value.

### HasNotes

`func (o *Component) HasNotes() bool`

HasNotes returns a boolean if a field has been set.

### GetUuid

`func (o *Component) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *Component) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *Component) SetUuid(v string)`

SetUuid sets Uuid field to given value.


### GetAuthor

`func (o *Component) GetAuthor() string`

GetAuthor returns the Author field if non-nil, zero value otherwise.

### GetAuthorOk

`func (o *Component) GetAuthorOk() (*string, bool)`

GetAuthorOk returns a tuple with the Author field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthor

`func (o *Component) SetAuthor(v string)`

SetAuthor sets Author field to given value.

### HasAuthor

`func (o *Component) HasAuthor() bool`

HasAuthor returns a boolean if a field has been set.

### GetMetrics

`func (o *Component) GetMetrics() DependencyMetrics`

GetMetrics returns the Metrics field if non-nil, zero value otherwise.

### GetMetricsOk

`func (o *Component) GetMetricsOk() (*DependencyMetrics, bool)`

GetMetricsOk returns a tuple with the Metrics field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMetrics

`func (o *Component) SetMetrics(v DependencyMetrics)`

SetMetrics sets Metrics field to given value.

### HasMetrics

`func (o *Component) HasMetrics() bool`

HasMetrics returns a boolean if a field has been set.

### GetRepositoryMeta

`func (o *Component) GetRepositoryMeta() RepositoryMetaComponent`

GetRepositoryMeta returns the RepositoryMeta field if non-nil, zero value otherwise.

### GetRepositoryMetaOk

`func (o *Component) GetRepositoryMetaOk() (*RepositoryMetaComponent, bool)`

GetRepositoryMetaOk returns a tuple with the RepositoryMeta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRepositoryMeta

`func (o *Component) SetRepositoryMeta(v RepositoryMetaComponent)`

SetRepositoryMeta sets RepositoryMeta field to given value.

### HasRepositoryMeta

`func (o *Component) HasRepositoryMeta() bool`

HasRepositoryMeta returns a boolean if a field has been set.

### GetDependencyGraph

`func (o *Component) GetDependencyGraph() []string`

GetDependencyGraph returns the DependencyGraph field if non-nil, zero value otherwise.

### GetDependencyGraphOk

`func (o *Component) GetDependencyGraphOk() (*[]string, bool)`

GetDependencyGraphOk returns a tuple with the DependencyGraph field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDependencyGraph

`func (o *Component) SetDependencyGraph(v []string)`

SetDependencyGraph sets DependencyGraph field to given value.

### HasDependencyGraph

`func (o *Component) HasDependencyGraph() bool`

HasDependencyGraph returns a boolean if a field has been set.

### GetExpandDependencyGraph

`func (o *Component) GetExpandDependencyGraph() bool`

GetExpandDependencyGraph returns the ExpandDependencyGraph field if non-nil, zero value otherwise.

### GetExpandDependencyGraphOk

`func (o *Component) GetExpandDependencyGraphOk() (*bool, bool)`

GetExpandDependencyGraphOk returns a tuple with the ExpandDependencyGraph field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpandDependencyGraph

`func (o *Component) SetExpandDependencyGraph(v bool)`

SetExpandDependencyGraph sets ExpandDependencyGraph field to given value.

### HasExpandDependencyGraph

`func (o *Component) HasExpandDependencyGraph() bool`

HasExpandDependencyGraph returns a boolean if a field has been set.

### GetIsInternal

`func (o *Component) GetIsInternal() bool`

GetIsInternal returns the IsInternal field if non-nil, zero value otherwise.

### GetIsInternalOk

`func (o *Component) GetIsInternalOk() (*bool, bool)`

GetIsInternalOk returns a tuple with the IsInternal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsInternal

`func (o *Component) SetIsInternal(v bool)`

SetIsInternal sets IsInternal field to given value.

### HasIsInternal

`func (o *Component) HasIsInternal() bool`

HasIsInternal returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


