/*
Dependency-Track API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 4.11.7
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// checks if the Project type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &Project{}

// Project struct for Project
type Project struct {
	Author                 *string               `json:"author,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
	Publisher              *string               `json:"publisher,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
	Manufacturer           *OrganizationalEntity `json:"manufacturer,omitempty"`
	Supplier               *OrganizationalEntity `json:"supplier,omitempty"`
	Group                  *string               `json:"group,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
	Name                   *string               `json:"name,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
	Description            *string               `json:"description,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
	Version                *string               `json:"version,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
	Classifier             *string               `json:"classifier,omitempty"`
	Cpe                    *string               "json:\"cpe,omitempty\" validate:\"regexp=(cpe:2\\\\.3:[aho\\\\*\\\\-](:(((\\\\?*|\\\\*?)([a-zA-Z0-9\\\\-\\\\._]|(\\\\\\\\[\\\\\\\\\\\\*\\\\?!\\\"#$$%&'\\\\(\\\\)\\\\+,\\/:;<=>@\\\\[\\\\]\\\\^`\\\\{\\\\|}~]))+(\\\\?*|\\\\*?))|[\\\\*\\\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\\\*\\\\-]))(:(((\\\\?*|\\\\*?)([a-zA-Z0-9\\\\-\\\\._]|(\\\\\\\\[\\\\\\\\\\\\*\\\\?!\\\"#$$%&'\\\\(\\\\)\\\\+,\\/:;<=>@\\\\[\\\\]\\\\^`\\\\{\\\\|}~]))+(\\\\?*|\\\\*?))|[\\\\*\\\\-])){4})|([c][pP][eE]:\\/[AHOaho]?(:[A-Za-z0-9\\\\._\\\\-~%]*){0,6})\""
	Purl                   *string               `json:"purl,omitempty"`
	SwidTagId              *string               `json:"swidTagId,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
	DirectDependencies     *string               `json:"directDependencies,omitempty"`
	Uuid                   string                `json:"uuid"`
	Parent                 *Project              `json:"parent,omitempty"`
	Children               []Project             `json:"children,omitempty"`
	Properties             []ProjectProperty     `json:"properties,omitempty"`
	Tags                   []Tag                 `json:"tags,omitempty"`
	LastBomImport          *float32              `json:"lastBomImport,omitempty"`
	LastBomImportFormat    *string               `json:"lastBomImportFormat,omitempty"`
	LastInheritedRiskScore *float64              `json:"lastInheritedRiskScore,omitempty"`
	Active                 *bool                 `json:"active,omitempty"`
	ExternalReferences     []ExternalReference   `json:"externalReferences,omitempty"`
	Metadata               *ProjectMetadata      `json:"metadata,omitempty"`
	Versions               []ProjectVersion      `json:"versions,omitempty"`
	Metrics                *ProjectMetrics       `json:"metrics,omitempty"`
	BomRef                 *string               `json:"bomRef,omitempty"`
}

type _Project Project

// NewProject instantiates a new Project object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewProject(uuid string) *Project {
	this := Project{}
	this.Uuid = uuid
	return &this
}

// NewProjectWithDefaults instantiates a new Project object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewProjectWithDefaults() *Project {
	this := Project{}
	return &this
}

// GetAuthor returns the Author field value if set, zero value otherwise.
func (o *Project) GetAuthor() string {
	if o == nil || IsNil(o.Author) {
		var ret string
		return ret
	}
	return *o.Author
}

// GetAuthorOk returns a tuple with the Author field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetAuthorOk() (*string, bool) {
	if o == nil || IsNil(o.Author) {
		return nil, false
	}
	return o.Author, true
}

// HasAuthor returns a boolean if a field has been set.
func (o *Project) HasAuthor() bool {
	if o != nil && !IsNil(o.Author) {
		return true
	}

	return false
}

// SetAuthor gets a reference to the given string and assigns it to the Author field.
func (o *Project) SetAuthor(v string) {
	o.Author = &v
}

// GetPublisher returns the Publisher field value if set, zero value otherwise.
func (o *Project) GetPublisher() string {
	if o == nil || IsNil(o.Publisher) {
		var ret string
		return ret
	}
	return *o.Publisher
}

// GetPublisherOk returns a tuple with the Publisher field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetPublisherOk() (*string, bool) {
	if o == nil || IsNil(o.Publisher) {
		return nil, false
	}
	return o.Publisher, true
}

// HasPublisher returns a boolean if a field has been set.
func (o *Project) HasPublisher() bool {
	if o != nil && !IsNil(o.Publisher) {
		return true
	}

	return false
}

// SetPublisher gets a reference to the given string and assigns it to the Publisher field.
func (o *Project) SetPublisher(v string) {
	o.Publisher = &v
}

// GetManufacturer returns the Manufacturer field value if set, zero value otherwise.
func (o *Project) GetManufacturer() OrganizationalEntity {
	if o == nil || IsNil(o.Manufacturer) {
		var ret OrganizationalEntity
		return ret
	}
	return *o.Manufacturer
}

// GetManufacturerOk returns a tuple with the Manufacturer field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetManufacturerOk() (*OrganizationalEntity, bool) {
	if o == nil || IsNil(o.Manufacturer) {
		return nil, false
	}
	return o.Manufacturer, true
}

// HasManufacturer returns a boolean if a field has been set.
func (o *Project) HasManufacturer() bool {
	if o != nil && !IsNil(o.Manufacturer) {
		return true
	}

	return false
}

// SetManufacturer gets a reference to the given OrganizationalEntity and assigns it to the Manufacturer field.
func (o *Project) SetManufacturer(v OrganizationalEntity) {
	o.Manufacturer = &v
}

// GetSupplier returns the Supplier field value if set, zero value otherwise.
func (o *Project) GetSupplier() OrganizationalEntity {
	if o == nil || IsNil(o.Supplier) {
		var ret OrganizationalEntity
		return ret
	}
	return *o.Supplier
}

// GetSupplierOk returns a tuple with the Supplier field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetSupplierOk() (*OrganizationalEntity, bool) {
	if o == nil || IsNil(o.Supplier) {
		return nil, false
	}
	return o.Supplier, true
}

// HasSupplier returns a boolean if a field has been set.
func (o *Project) HasSupplier() bool {
	if o != nil && !IsNil(o.Supplier) {
		return true
	}

	return false
}

// SetSupplier gets a reference to the given OrganizationalEntity and assigns it to the Supplier field.
func (o *Project) SetSupplier(v OrganizationalEntity) {
	o.Supplier = &v
}

// GetGroup returns the Group field value if set, zero value otherwise.
func (o *Project) GetGroup() string {
	if o == nil || IsNil(o.Group) {
		var ret string
		return ret
	}
	return *o.Group
}

// GetGroupOk returns a tuple with the Group field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetGroupOk() (*string, bool) {
	if o == nil || IsNil(o.Group) {
		return nil, false
	}
	return o.Group, true
}

// HasGroup returns a boolean if a field has been set.
func (o *Project) HasGroup() bool {
	if o != nil && !IsNil(o.Group) {
		return true
	}

	return false
}

// SetGroup gets a reference to the given string and assigns it to the Group field.
func (o *Project) SetGroup(v string) {
	o.Group = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *Project) GetName() string {
	if o == nil || IsNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetNameOk() (*string, bool) {
	if o == nil || IsNil(o.Name) {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *Project) HasName() bool {
	if o != nil && !IsNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *Project) SetName(v string) {
	o.Name = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *Project) GetDescription() string {
	if o == nil || IsNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetDescriptionOk() (*string, bool) {
	if o == nil || IsNil(o.Description) {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *Project) HasDescription() bool {
	if o != nil && !IsNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *Project) SetDescription(v string) {
	o.Description = &v
}

// GetVersion returns the Version field value if set, zero value otherwise.
func (o *Project) GetVersion() string {
	if o == nil || IsNil(o.Version) {
		var ret string
		return ret
	}
	return *o.Version
}

// GetVersionOk returns a tuple with the Version field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetVersionOk() (*string, bool) {
	if o == nil || IsNil(o.Version) {
		return nil, false
	}
	return o.Version, true
}

// HasVersion returns a boolean if a field has been set.
func (o *Project) HasVersion() bool {
	if o != nil && !IsNil(o.Version) {
		return true
	}

	return false
}

// SetVersion gets a reference to the given string and assigns it to the Version field.
func (o *Project) SetVersion(v string) {
	o.Version = &v
}

// GetClassifier returns the Classifier field value if set, zero value otherwise.
func (o *Project) GetClassifier() string {
	if o == nil || IsNil(o.Classifier) {
		var ret string
		return ret
	}
	return *o.Classifier
}

// GetClassifierOk returns a tuple with the Classifier field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetClassifierOk() (*string, bool) {
	if o == nil || IsNil(o.Classifier) {
		return nil, false
	}
	return o.Classifier, true
}

// HasClassifier returns a boolean if a field has been set.
func (o *Project) HasClassifier() bool {
	if o != nil && !IsNil(o.Classifier) {
		return true
	}

	return false
}

// SetClassifier gets a reference to the given string and assigns it to the Classifier field.
func (o *Project) SetClassifier(v string) {
	o.Classifier = &v
}

// GetCpe returns the Cpe field value if set, zero value otherwise.
func (o *Project) GetCpe() string {
	if o == nil || IsNil(o.Cpe) {
		var ret string
		return ret
	}
	return *o.Cpe
}

// GetCpeOk returns a tuple with the Cpe field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetCpeOk() (*string, bool) {
	if o == nil || IsNil(o.Cpe) {
		return nil, false
	}
	return o.Cpe, true
}

// HasCpe returns a boolean if a field has been set.
func (o *Project) HasCpe() bool {
	if o != nil && !IsNil(o.Cpe) {
		return true
	}

	return false
}

// SetCpe gets a reference to the given string and assigns it to the Cpe field.
func (o *Project) SetCpe(v string) {
	o.Cpe = &v
}

// GetPurl returns the Purl field value if set, zero value otherwise.
func (o *Project) GetPurl() string {
	if o == nil || IsNil(o.Purl) {
		var ret string
		return ret
	}
	return *o.Purl
}

// GetPurlOk returns a tuple with the Purl field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetPurlOk() (*string, bool) {
	if o == nil || IsNil(o.Purl) {
		return nil, false
	}
	return o.Purl, true
}

// HasPurl returns a boolean if a field has been set.
func (o *Project) HasPurl() bool {
	if o != nil && !IsNil(o.Purl) {
		return true
	}

	return false
}

// SetPurl gets a reference to the given string and assigns it to the Purl field.
func (o *Project) SetPurl(v string) {
	o.Purl = &v
}

// GetSwidTagId returns the SwidTagId field value if set, zero value otherwise.
func (o *Project) GetSwidTagId() string {
	if o == nil || IsNil(o.SwidTagId) {
		var ret string
		return ret
	}
	return *o.SwidTagId
}

// GetSwidTagIdOk returns a tuple with the SwidTagId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetSwidTagIdOk() (*string, bool) {
	if o == nil || IsNil(o.SwidTagId) {
		return nil, false
	}
	return o.SwidTagId, true
}

// HasSwidTagId returns a boolean if a field has been set.
func (o *Project) HasSwidTagId() bool {
	if o != nil && !IsNil(o.SwidTagId) {
		return true
	}

	return false
}

// SetSwidTagId gets a reference to the given string and assigns it to the SwidTagId field.
func (o *Project) SetSwidTagId(v string) {
	o.SwidTagId = &v
}

// GetDirectDependencies returns the DirectDependencies field value if set, zero value otherwise.
func (o *Project) GetDirectDependencies() string {
	if o == nil || IsNil(o.DirectDependencies) {
		var ret string
		return ret
	}
	return *o.DirectDependencies
}

// GetDirectDependenciesOk returns a tuple with the DirectDependencies field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetDirectDependenciesOk() (*string, bool) {
	if o == nil || IsNil(o.DirectDependencies) {
		return nil, false
	}
	return o.DirectDependencies, true
}

// HasDirectDependencies returns a boolean if a field has been set.
func (o *Project) HasDirectDependencies() bool {
	if o != nil && !IsNil(o.DirectDependencies) {
		return true
	}

	return false
}

// SetDirectDependencies gets a reference to the given string and assigns it to the DirectDependencies field.
func (o *Project) SetDirectDependencies(v string) {
	o.DirectDependencies = &v
}

// GetUuid returns the Uuid field value
func (o *Project) GetUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value
// and a boolean to check if the value has been set.
func (o *Project) GetUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Uuid, true
}

// SetUuid sets field value
func (o *Project) SetUuid(v string) {
	o.Uuid = v
}

// GetParent returns the Parent field value if set, zero value otherwise.
func (o *Project) GetParent() Project {
	if o == nil || IsNil(o.Parent) {
		var ret Project
		return ret
	}
	return *o.Parent
}

// GetParentOk returns a tuple with the Parent field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetParentOk() (*Project, bool) {
	if o == nil || IsNil(o.Parent) {
		return nil, false
	}
	return o.Parent, true
}

// HasParent returns a boolean if a field has been set.
func (o *Project) HasParent() bool {
	if o != nil && !IsNil(o.Parent) {
		return true
	}

	return false
}

// SetParent gets a reference to the given Project and assigns it to the Parent field.
func (o *Project) SetParent(v Project) {
	o.Parent = &v
}

// GetChildren returns the Children field value if set, zero value otherwise.
func (o *Project) GetChildren() []Project {
	if o == nil || IsNil(o.Children) {
		var ret []Project
		return ret
	}
	return o.Children
}

// GetChildrenOk returns a tuple with the Children field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetChildrenOk() ([]Project, bool) {
	if o == nil || IsNil(o.Children) {
		return nil, false
	}
	return o.Children, true
}

// HasChildren returns a boolean if a field has been set.
func (o *Project) HasChildren() bool {
	if o != nil && !IsNil(o.Children) {
		return true
	}

	return false
}

// SetChildren gets a reference to the given []Project and assigns it to the Children field.
func (o *Project) SetChildren(v []Project) {
	o.Children = v
}

// GetProperties returns the Properties field value if set, zero value otherwise.
func (o *Project) GetProperties() []ProjectProperty {
	if o == nil || IsNil(o.Properties) {
		var ret []ProjectProperty
		return ret
	}
	return o.Properties
}

// GetPropertiesOk returns a tuple with the Properties field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetPropertiesOk() ([]ProjectProperty, bool) {
	if o == nil || IsNil(o.Properties) {
		return nil, false
	}
	return o.Properties, true
}

// HasProperties returns a boolean if a field has been set.
func (o *Project) HasProperties() bool {
	if o != nil && !IsNil(o.Properties) {
		return true
	}

	return false
}

// SetProperties gets a reference to the given []ProjectProperty and assigns it to the Properties field.
func (o *Project) SetProperties(v []ProjectProperty) {
	o.Properties = v
}

// GetTags returns the Tags field value if set, zero value otherwise.
func (o *Project) GetTags() []Tag {
	if o == nil || IsNil(o.Tags) {
		var ret []Tag
		return ret
	}
	return o.Tags
}

// GetTagsOk returns a tuple with the Tags field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetTagsOk() ([]Tag, bool) {
	if o == nil || IsNil(o.Tags) {
		return nil, false
	}
	return o.Tags, true
}

// HasTags returns a boolean if a field has been set.
func (o *Project) HasTags() bool {
	if o != nil && !IsNil(o.Tags) {
		return true
	}

	return false
}

// SetTags gets a reference to the given []Tag and assigns it to the Tags field.
func (o *Project) SetTags(v []Tag) {
	o.Tags = v
}

// GetLastBomImport returns the LastBomImport field value if set, zero value otherwise.
func (o *Project) GetLastBomImport() float32 {
	if o == nil || IsNil(o.LastBomImport) {
		var ret float32
		return ret
	}
	return *o.LastBomImport
}

// GetLastBomImportOk returns a tuple with the LastBomImport field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetLastBomImportOk() (*float32, bool) {
	if o == nil || IsNil(o.LastBomImport) {
		return nil, false
	}
	return o.LastBomImport, true
}

// HasLastBomImport returns a boolean if a field has been set.
func (o *Project) HasLastBomImport() bool {
	if o != nil && !IsNil(o.LastBomImport) {
		return true
	}

	return false
}

// SetLastBomImport gets a reference to the given float32 and assigns it to the LastBomImport field.
func (o *Project) SetLastBomImport(v float32) {
	o.LastBomImport = &v
}

// GetLastBomImportFormat returns the LastBomImportFormat field value if set, zero value otherwise.
func (o *Project) GetLastBomImportFormat() string {
	if o == nil || IsNil(o.LastBomImportFormat) {
		var ret string
		return ret
	}
	return *o.LastBomImportFormat
}

// GetLastBomImportFormatOk returns a tuple with the LastBomImportFormat field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetLastBomImportFormatOk() (*string, bool) {
	if o == nil || IsNil(o.LastBomImportFormat) {
		return nil, false
	}
	return o.LastBomImportFormat, true
}

// HasLastBomImportFormat returns a boolean if a field has been set.
func (o *Project) HasLastBomImportFormat() bool {
	if o != nil && !IsNil(o.LastBomImportFormat) {
		return true
	}

	return false
}

// SetLastBomImportFormat gets a reference to the given string and assigns it to the LastBomImportFormat field.
func (o *Project) SetLastBomImportFormat(v string) {
	o.LastBomImportFormat = &v
}

// GetLastInheritedRiskScore returns the LastInheritedRiskScore field value if set, zero value otherwise.
func (o *Project) GetLastInheritedRiskScore() float64 {
	if o == nil || IsNil(o.LastInheritedRiskScore) {
		var ret float64
		return ret
	}
	return *o.LastInheritedRiskScore
}

// GetLastInheritedRiskScoreOk returns a tuple with the LastInheritedRiskScore field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetLastInheritedRiskScoreOk() (*float64, bool) {
	if o == nil || IsNil(o.LastInheritedRiskScore) {
		return nil, false
	}
	return o.LastInheritedRiskScore, true
}

// HasLastInheritedRiskScore returns a boolean if a field has been set.
func (o *Project) HasLastInheritedRiskScore() bool {
	if o != nil && !IsNil(o.LastInheritedRiskScore) {
		return true
	}

	return false
}

// SetLastInheritedRiskScore gets a reference to the given float64 and assigns it to the LastInheritedRiskScore field.
func (o *Project) SetLastInheritedRiskScore(v float64) {
	o.LastInheritedRiskScore = &v
}

// GetActive returns the Active field value if set, zero value otherwise.
func (o *Project) GetActive() bool {
	if o == nil || IsNil(o.Active) {
		var ret bool
		return ret
	}
	return *o.Active
}

// GetActiveOk returns a tuple with the Active field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetActiveOk() (*bool, bool) {
	if o == nil || IsNil(o.Active) {
		return nil, false
	}
	return o.Active, true
}

// HasActive returns a boolean if a field has been set.
func (o *Project) HasActive() bool {
	if o != nil && !IsNil(o.Active) {
		return true
	}

	return false
}

// SetActive gets a reference to the given bool and assigns it to the Active field.
func (o *Project) SetActive(v bool) {
	o.Active = &v
}

// GetExternalReferences returns the ExternalReferences field value if set, zero value otherwise.
func (o *Project) GetExternalReferences() []ExternalReference {
	if o == nil || IsNil(o.ExternalReferences) {
		var ret []ExternalReference
		return ret
	}
	return o.ExternalReferences
}

// GetExternalReferencesOk returns a tuple with the ExternalReferences field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetExternalReferencesOk() ([]ExternalReference, bool) {
	if o == nil || IsNil(o.ExternalReferences) {
		return nil, false
	}
	return o.ExternalReferences, true
}

// HasExternalReferences returns a boolean if a field has been set.
func (o *Project) HasExternalReferences() bool {
	if o != nil && !IsNil(o.ExternalReferences) {
		return true
	}

	return false
}

// SetExternalReferences gets a reference to the given []ExternalReference and assigns it to the ExternalReferences field.
func (o *Project) SetExternalReferences(v []ExternalReference) {
	o.ExternalReferences = v
}

// GetMetadata returns the Metadata field value if set, zero value otherwise.
func (o *Project) GetMetadata() ProjectMetadata {
	if o == nil || IsNil(o.Metadata) {
		var ret ProjectMetadata
		return ret
	}
	return *o.Metadata
}

// GetMetadataOk returns a tuple with the Metadata field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetMetadataOk() (*ProjectMetadata, bool) {
	if o == nil || IsNil(o.Metadata) {
		return nil, false
	}
	return o.Metadata, true
}

// HasMetadata returns a boolean if a field has been set.
func (o *Project) HasMetadata() bool {
	if o != nil && !IsNil(o.Metadata) {
		return true
	}

	return false
}

// SetMetadata gets a reference to the given ProjectMetadata and assigns it to the Metadata field.
func (o *Project) SetMetadata(v ProjectMetadata) {
	o.Metadata = &v
}

// GetVersions returns the Versions field value if set, zero value otherwise.
func (o *Project) GetVersions() []ProjectVersion {
	if o == nil || IsNil(o.Versions) {
		var ret []ProjectVersion
		return ret
	}
	return o.Versions
}

// GetVersionsOk returns a tuple with the Versions field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetVersionsOk() ([]ProjectVersion, bool) {
	if o == nil || IsNil(o.Versions) {
		return nil, false
	}
	return o.Versions, true
}

// HasVersions returns a boolean if a field has been set.
func (o *Project) HasVersions() bool {
	if o != nil && !IsNil(o.Versions) {
		return true
	}

	return false
}

// SetVersions gets a reference to the given []ProjectVersion and assigns it to the Versions field.
func (o *Project) SetVersions(v []ProjectVersion) {
	o.Versions = v
}

// GetMetrics returns the Metrics field value if set, zero value otherwise.
func (o *Project) GetMetrics() ProjectMetrics {
	if o == nil || IsNil(o.Metrics) {
		var ret ProjectMetrics
		return ret
	}
	return *o.Metrics
}

// GetMetricsOk returns a tuple with the Metrics field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetMetricsOk() (*ProjectMetrics, bool) {
	if o == nil || IsNil(o.Metrics) {
		return nil, false
	}
	return o.Metrics, true
}

// HasMetrics returns a boolean if a field has been set.
func (o *Project) HasMetrics() bool {
	if o != nil && !IsNil(o.Metrics) {
		return true
	}

	return false
}

// SetMetrics gets a reference to the given ProjectMetrics and assigns it to the Metrics field.
func (o *Project) SetMetrics(v ProjectMetrics) {
	o.Metrics = &v
}

// GetBomRef returns the BomRef field value if set, zero value otherwise.
func (o *Project) GetBomRef() string {
	if o == nil || IsNil(o.BomRef) {
		var ret string
		return ret
	}
	return *o.BomRef
}

// GetBomRefOk returns a tuple with the BomRef field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Project) GetBomRefOk() (*string, bool) {
	if o == nil || IsNil(o.BomRef) {
		return nil, false
	}
	return o.BomRef, true
}

// HasBomRef returns a boolean if a field has been set.
func (o *Project) HasBomRef() bool {
	if o != nil && !IsNil(o.BomRef) {
		return true
	}

	return false
}

// SetBomRef gets a reference to the given string and assigns it to the BomRef field.
func (o *Project) SetBomRef(v string) {
	o.BomRef = &v
}

func (o Project) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o Project) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Author) {
		toSerialize["author"] = o.Author
	}
	if !IsNil(o.Publisher) {
		toSerialize["publisher"] = o.Publisher
	}
	if !IsNil(o.Manufacturer) {
		toSerialize["manufacturer"] = o.Manufacturer
	}
	if !IsNil(o.Supplier) {
		toSerialize["supplier"] = o.Supplier
	}
	if !IsNil(o.Group) {
		toSerialize["group"] = o.Group
	}
	if !IsNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !IsNil(o.Description) {
		toSerialize["description"] = o.Description
	}
	if !IsNil(o.Version) {
		toSerialize["version"] = o.Version
	}
	if !IsNil(o.Classifier) {
		toSerialize["classifier"] = o.Classifier
	}
	if !IsNil(o.Cpe) {
		toSerialize["cpe"] = o.Cpe
	}
	if !IsNil(o.Purl) {
		toSerialize["purl"] = o.Purl
	}
	if !IsNil(o.SwidTagId) {
		toSerialize["swidTagId"] = o.SwidTagId
	}
	if !IsNil(o.DirectDependencies) {
		toSerialize["directDependencies"] = o.DirectDependencies
	}
	toSerialize["uuid"] = o.Uuid
	if !IsNil(o.Parent) {
		toSerialize["parent"] = o.Parent
	}
	if !IsNil(o.Children) {
		toSerialize["children"] = o.Children
	}
	if !IsNil(o.Properties) {
		toSerialize["properties"] = o.Properties
	}
	if !IsNil(o.Tags) {
		toSerialize["tags"] = o.Tags
	}
	if !IsNil(o.LastBomImport) {
		toSerialize["lastBomImport"] = o.LastBomImport
	}
	if !IsNil(o.LastBomImportFormat) {
		toSerialize["lastBomImportFormat"] = o.LastBomImportFormat
	}
	if !IsNil(o.LastInheritedRiskScore) {
		toSerialize["lastInheritedRiskScore"] = o.LastInheritedRiskScore
	}
	if !IsNil(o.Active) {
		toSerialize["active"] = o.Active
	}
	if !IsNil(o.ExternalReferences) {
		toSerialize["externalReferences"] = o.ExternalReferences
	}
	if !IsNil(o.Metadata) {
		toSerialize["metadata"] = o.Metadata
	}
	if !IsNil(o.Versions) {
		toSerialize["versions"] = o.Versions
	}
	if !IsNil(o.Metrics) {
		toSerialize["metrics"] = o.Metrics
	}
	if !IsNil(o.BomRef) {
		toSerialize["bomRef"] = o.BomRef
	}
	return toSerialize, nil
}

func (o *Project) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"uuid",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(data, &allProperties)

	if err != nil {
		return err
	}

	for _, requiredProperty := range requiredProperties {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varProject := _Project{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varProject)

	if err != nil {
		return err
	}

	*o = Project(varProject)

	return err
}

type NullableProject struct {
	value *Project
	isSet bool
}

func (v NullableProject) Get() *Project {
	return v.value
}

func (v *NullableProject) Set(val *Project) {
	v.value = val
	v.isSet = true
}

func (v NullableProject) IsSet() bool {
	return v.isSet
}

func (v *NullableProject) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableProject(val *Project) *NullableProject {
	return &NullableProject{value: val, isSet: true}
}

func (v NullableProject) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableProject) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
