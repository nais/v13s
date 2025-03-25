# License

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**LicenseGroups** | Pointer to [**[]LicenseGroup**](LicenseGroup.md) |  | [optional] 
**Uuid** | **string** |  | 
**Name** | Pointer to **string** |  | [optional] 
**LicenseText** | Pointer to **string** |  | [optional] 
**StandardLicenseTemplate** | Pointer to **string** |  | [optional] 
**StandardLicenseHeader** | Pointer to **string** |  | [optional] 
**LicenseComments** | Pointer to **string** |  | [optional] 
**LicenseId** | Pointer to **string** |  | [optional] 
**IsOsiApproved** | Pointer to **bool** |  | [optional] 
**IsFsfLibre** | Pointer to **bool** |  | [optional] 
**IsDeprecatedLicenseId** | Pointer to **bool** |  | [optional] 
**IsCustomLicense** | Pointer to **bool** |  | [optional] 
**SeeAlso** | Pointer to **[]string** |  | [optional] 

## Methods

### NewLicense

`func NewLicense(uuid string, ) *License`

NewLicense instantiates a new License object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewLicenseWithDefaults

`func NewLicenseWithDefaults() *License`

NewLicenseWithDefaults instantiates a new License object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLicenseGroups

`func (o *License) GetLicenseGroups() []LicenseGroup`

GetLicenseGroups returns the LicenseGroups field if non-nil, zero value otherwise.

### GetLicenseGroupsOk

`func (o *License) GetLicenseGroupsOk() (*[]LicenseGroup, bool)`

GetLicenseGroupsOk returns a tuple with the LicenseGroups field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLicenseGroups

`func (o *License) SetLicenseGroups(v []LicenseGroup)`

SetLicenseGroups sets LicenseGroups field to given value.

### HasLicenseGroups

`func (o *License) HasLicenseGroups() bool`

HasLicenseGroups returns a boolean if a field has been set.

### GetUuid

`func (o *License) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *License) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *License) SetUuid(v string)`

SetUuid sets Uuid field to given value.


### GetName

`func (o *License) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *License) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *License) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *License) HasName() bool`

HasName returns a boolean if a field has been set.

### GetLicenseText

`func (o *License) GetLicenseText() string`

GetLicenseText returns the LicenseText field if non-nil, zero value otherwise.

### GetLicenseTextOk

`func (o *License) GetLicenseTextOk() (*string, bool)`

GetLicenseTextOk returns a tuple with the LicenseText field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLicenseText

`func (o *License) SetLicenseText(v string)`

SetLicenseText sets LicenseText field to given value.

### HasLicenseText

`func (o *License) HasLicenseText() bool`

HasLicenseText returns a boolean if a field has been set.

### GetStandardLicenseTemplate

`func (o *License) GetStandardLicenseTemplate() string`

GetStandardLicenseTemplate returns the StandardLicenseTemplate field if non-nil, zero value otherwise.

### GetStandardLicenseTemplateOk

`func (o *License) GetStandardLicenseTemplateOk() (*string, bool)`

GetStandardLicenseTemplateOk returns a tuple with the StandardLicenseTemplate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStandardLicenseTemplate

`func (o *License) SetStandardLicenseTemplate(v string)`

SetStandardLicenseTemplate sets StandardLicenseTemplate field to given value.

### HasStandardLicenseTemplate

`func (o *License) HasStandardLicenseTemplate() bool`

HasStandardLicenseTemplate returns a boolean if a field has been set.

### GetStandardLicenseHeader

`func (o *License) GetStandardLicenseHeader() string`

GetStandardLicenseHeader returns the StandardLicenseHeader field if non-nil, zero value otherwise.

### GetStandardLicenseHeaderOk

`func (o *License) GetStandardLicenseHeaderOk() (*string, bool)`

GetStandardLicenseHeaderOk returns a tuple with the StandardLicenseHeader field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStandardLicenseHeader

`func (o *License) SetStandardLicenseHeader(v string)`

SetStandardLicenseHeader sets StandardLicenseHeader field to given value.

### HasStandardLicenseHeader

`func (o *License) HasStandardLicenseHeader() bool`

HasStandardLicenseHeader returns a boolean if a field has been set.

### GetLicenseComments

`func (o *License) GetLicenseComments() string`

GetLicenseComments returns the LicenseComments field if non-nil, zero value otherwise.

### GetLicenseCommentsOk

`func (o *License) GetLicenseCommentsOk() (*string, bool)`

GetLicenseCommentsOk returns a tuple with the LicenseComments field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLicenseComments

`func (o *License) SetLicenseComments(v string)`

SetLicenseComments sets LicenseComments field to given value.

### HasLicenseComments

`func (o *License) HasLicenseComments() bool`

HasLicenseComments returns a boolean if a field has been set.

### GetLicenseId

`func (o *License) GetLicenseId() string`

GetLicenseId returns the LicenseId field if non-nil, zero value otherwise.

### GetLicenseIdOk

`func (o *License) GetLicenseIdOk() (*string, bool)`

GetLicenseIdOk returns a tuple with the LicenseId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLicenseId

`func (o *License) SetLicenseId(v string)`

SetLicenseId sets LicenseId field to given value.

### HasLicenseId

`func (o *License) HasLicenseId() bool`

HasLicenseId returns a boolean if a field has been set.

### GetIsOsiApproved

`func (o *License) GetIsOsiApproved() bool`

GetIsOsiApproved returns the IsOsiApproved field if non-nil, zero value otherwise.

### GetIsOsiApprovedOk

`func (o *License) GetIsOsiApprovedOk() (*bool, bool)`

GetIsOsiApprovedOk returns a tuple with the IsOsiApproved field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsOsiApproved

`func (o *License) SetIsOsiApproved(v bool)`

SetIsOsiApproved sets IsOsiApproved field to given value.

### HasIsOsiApproved

`func (o *License) HasIsOsiApproved() bool`

HasIsOsiApproved returns a boolean if a field has been set.

### GetIsFsfLibre

`func (o *License) GetIsFsfLibre() bool`

GetIsFsfLibre returns the IsFsfLibre field if non-nil, zero value otherwise.

### GetIsFsfLibreOk

`func (o *License) GetIsFsfLibreOk() (*bool, bool)`

GetIsFsfLibreOk returns a tuple with the IsFsfLibre field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsFsfLibre

`func (o *License) SetIsFsfLibre(v bool)`

SetIsFsfLibre sets IsFsfLibre field to given value.

### HasIsFsfLibre

`func (o *License) HasIsFsfLibre() bool`

HasIsFsfLibre returns a boolean if a field has been set.

### GetIsDeprecatedLicenseId

`func (o *License) GetIsDeprecatedLicenseId() bool`

GetIsDeprecatedLicenseId returns the IsDeprecatedLicenseId field if non-nil, zero value otherwise.

### GetIsDeprecatedLicenseIdOk

`func (o *License) GetIsDeprecatedLicenseIdOk() (*bool, bool)`

GetIsDeprecatedLicenseIdOk returns a tuple with the IsDeprecatedLicenseId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsDeprecatedLicenseId

`func (o *License) SetIsDeprecatedLicenseId(v bool)`

SetIsDeprecatedLicenseId sets IsDeprecatedLicenseId field to given value.

### HasIsDeprecatedLicenseId

`func (o *License) HasIsDeprecatedLicenseId() bool`

HasIsDeprecatedLicenseId returns a boolean if a field has been set.

### GetIsCustomLicense

`func (o *License) GetIsCustomLicense() bool`

GetIsCustomLicense returns the IsCustomLicense field if non-nil, zero value otherwise.

### GetIsCustomLicenseOk

`func (o *License) GetIsCustomLicenseOk() (*bool, bool)`

GetIsCustomLicenseOk returns a tuple with the IsCustomLicense field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsCustomLicense

`func (o *License) SetIsCustomLicense(v bool)`

SetIsCustomLicense sets IsCustomLicense field to given value.

### HasIsCustomLicense

`func (o *License) HasIsCustomLicense() bool`

HasIsCustomLicense returns a boolean if a field has been set.

### GetSeeAlso

`func (o *License) GetSeeAlso() []string`

GetSeeAlso returns the SeeAlso field if non-nil, zero value otherwise.

### GetSeeAlsoOk

`func (o *License) GetSeeAlsoOk() (*[]string, bool)`

GetSeeAlsoOk returns a tuple with the SeeAlso field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSeeAlso

`func (o *License) SetSeeAlso(v []string)`

SetSeeAlso sets SeeAlso field to given value.

### HasSeeAlso

`func (o *License) HasSeeAlso() bool`

HasSeeAlso returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


