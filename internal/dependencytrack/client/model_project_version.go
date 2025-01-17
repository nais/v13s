/*
Dependency-Track API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 4.11.7
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
)

// checks if the ProjectVersion type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ProjectVersion{}

// ProjectVersion struct for ProjectVersion
type ProjectVersion struct {
	Uuid    *string `json:"uuid,omitempty"`
	Version *string `json:"version,omitempty"`
}

// NewProjectVersion instantiates a new ProjectVersion object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewProjectVersion() *ProjectVersion {
	this := ProjectVersion{}
	return &this
}

// NewProjectVersionWithDefaults instantiates a new ProjectVersion object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewProjectVersionWithDefaults() *ProjectVersion {
	this := ProjectVersion{}
	return &this
}

// GetUuid returns the Uuid field value if set, zero value otherwise.
func (o *ProjectVersion) GetUuid() string {
	if o == nil || IsNil(o.Uuid) {
		var ret string
		return ret
	}
	return *o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ProjectVersion) GetUuidOk() (*string, bool) {
	if o == nil || IsNil(o.Uuid) {
		return nil, false
	}
	return o.Uuid, true
}

// HasUuid returns a boolean if a field has been set.
func (o *ProjectVersion) HasUuid() bool {
	if o != nil && !IsNil(o.Uuid) {
		return true
	}

	return false
}

// SetUuid gets a reference to the given string and assigns it to the Uuid field.
func (o *ProjectVersion) SetUuid(v string) {
	o.Uuid = &v
}

// GetVersion returns the Version field value if set, zero value otherwise.
func (o *ProjectVersion) GetVersion() string {
	if o == nil || IsNil(o.Version) {
		var ret string
		return ret
	}
	return *o.Version
}

// GetVersionOk returns a tuple with the Version field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ProjectVersion) GetVersionOk() (*string, bool) {
	if o == nil || IsNil(o.Version) {
		return nil, false
	}
	return o.Version, true
}

// HasVersion returns a boolean if a field has been set.
func (o *ProjectVersion) HasVersion() bool {
	if o != nil && !IsNil(o.Version) {
		return true
	}

	return false
}

// SetVersion gets a reference to the given string and assigns it to the Version field.
func (o *ProjectVersion) SetVersion(v string) {
	o.Version = &v
}

func (o ProjectVersion) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ProjectVersion) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Uuid) {
		toSerialize["uuid"] = o.Uuid
	}
	if !IsNil(o.Version) {
		toSerialize["version"] = o.Version
	}
	return toSerialize, nil
}

type NullableProjectVersion struct {
	value *ProjectVersion
	isSet bool
}

func (v NullableProjectVersion) Get() *ProjectVersion {
	return v.value
}

func (v *NullableProjectVersion) Set(val *ProjectVersion) {
	v.value = val
	v.isSet = true
}

func (v NullableProjectVersion) IsSet() bool {
	return v.isSet
}

func (v *NullableProjectVersion) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableProjectVersion(val *ProjectVersion) *NullableProjectVersion {
	return &NullableProjectVersion{value: val, isSet: true}
}

func (v NullableProjectVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableProjectVersion) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}