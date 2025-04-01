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

// checks if the DependencyGraphResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &DependencyGraphResponse{}

// DependencyGraphResponse struct for DependencyGraphResponse
type DependencyGraphResponse struct {
	Uuid *string `json:"uuid,omitempty"`
	Name *string `json:"name,omitempty"`
	Version *string `json:"version,omitempty"`
	Purl *string `json:"purl,omitempty"`
	DirectDependencies *string `json:"directDependencies,omitempty"`
	LatestVersion *string `json:"latestVersion,omitempty"`
}

// NewDependencyGraphResponse instantiates a new DependencyGraphResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDependencyGraphResponse() *DependencyGraphResponse {
	this := DependencyGraphResponse{}
	return &this
}

// NewDependencyGraphResponseWithDefaults instantiates a new DependencyGraphResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDependencyGraphResponseWithDefaults() *DependencyGraphResponse {
	this := DependencyGraphResponse{}
	return &this
}

// GetUuid returns the Uuid field value if set, zero value otherwise.
func (o *DependencyGraphResponse) GetUuid() string {
	if o == nil || IsNil(o.Uuid) {
		var ret string
		return ret
	}
	return *o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DependencyGraphResponse) GetUuidOk() (*string, bool) {
	if o == nil || IsNil(o.Uuid) {
		return nil, false
	}
	return o.Uuid, true
}

// HasUuid returns a boolean if a field has been set.
func (o *DependencyGraphResponse) HasUuid() bool {
	if o != nil && !IsNil(o.Uuid) {
		return true
	}

	return false
}

// SetUuid gets a reference to the given string and assigns it to the Uuid field.
func (o *DependencyGraphResponse) SetUuid(v string) {
	o.Uuid = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *DependencyGraphResponse) GetName() string {
	if o == nil || IsNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DependencyGraphResponse) GetNameOk() (*string, bool) {
	if o == nil || IsNil(o.Name) {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *DependencyGraphResponse) HasName() bool {
	if o != nil && !IsNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *DependencyGraphResponse) SetName(v string) {
	o.Name = &v
}

// GetVersion returns the Version field value if set, zero value otherwise.
func (o *DependencyGraphResponse) GetVersion() string {
	if o == nil || IsNil(o.Version) {
		var ret string
		return ret
	}
	return *o.Version
}

// GetVersionOk returns a tuple with the Version field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DependencyGraphResponse) GetVersionOk() (*string, bool) {
	if o == nil || IsNil(o.Version) {
		return nil, false
	}
	return o.Version, true
}

// HasVersion returns a boolean if a field has been set.
func (o *DependencyGraphResponse) HasVersion() bool {
	if o != nil && !IsNil(o.Version) {
		return true
	}

	return false
}

// SetVersion gets a reference to the given string and assigns it to the Version field.
func (o *DependencyGraphResponse) SetVersion(v string) {
	o.Version = &v
}

// GetPurl returns the Purl field value if set, zero value otherwise.
func (o *DependencyGraphResponse) GetPurl() string {
	if o == nil || IsNil(o.Purl) {
		var ret string
		return ret
	}
	return *o.Purl
}

// GetPurlOk returns a tuple with the Purl field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DependencyGraphResponse) GetPurlOk() (*string, bool) {
	if o == nil || IsNil(o.Purl) {
		return nil, false
	}
	return o.Purl, true
}

// HasPurl returns a boolean if a field has been set.
func (o *DependencyGraphResponse) HasPurl() bool {
	if o != nil && !IsNil(o.Purl) {
		return true
	}

	return false
}

// SetPurl gets a reference to the given string and assigns it to the Purl field.
func (o *DependencyGraphResponse) SetPurl(v string) {
	o.Purl = &v
}

// GetDirectDependencies returns the DirectDependencies field value if set, zero value otherwise.
func (o *DependencyGraphResponse) GetDirectDependencies() string {
	if o == nil || IsNil(o.DirectDependencies) {
		var ret string
		return ret
	}
	return *o.DirectDependencies
}

// GetDirectDependenciesOk returns a tuple with the DirectDependencies field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DependencyGraphResponse) GetDirectDependenciesOk() (*string, bool) {
	if o == nil || IsNil(o.DirectDependencies) {
		return nil, false
	}
	return o.DirectDependencies, true
}

// HasDirectDependencies returns a boolean if a field has been set.
func (o *DependencyGraphResponse) HasDirectDependencies() bool {
	if o != nil && !IsNil(o.DirectDependencies) {
		return true
	}

	return false
}

// SetDirectDependencies gets a reference to the given string and assigns it to the DirectDependencies field.
func (o *DependencyGraphResponse) SetDirectDependencies(v string) {
	o.DirectDependencies = &v
}

// GetLatestVersion returns the LatestVersion field value if set, zero value otherwise.
func (o *DependencyGraphResponse) GetLatestVersion() string {
	if o == nil || IsNil(o.LatestVersion) {
		var ret string
		return ret
	}
	return *o.LatestVersion
}

// GetLatestVersionOk returns a tuple with the LatestVersion field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DependencyGraphResponse) GetLatestVersionOk() (*string, bool) {
	if o == nil || IsNil(o.LatestVersion) {
		return nil, false
	}
	return o.LatestVersion, true
}

// HasLatestVersion returns a boolean if a field has been set.
func (o *DependencyGraphResponse) HasLatestVersion() bool {
	if o != nil && !IsNil(o.LatestVersion) {
		return true
	}

	return false
}

// SetLatestVersion gets a reference to the given string and assigns it to the LatestVersion field.
func (o *DependencyGraphResponse) SetLatestVersion(v string) {
	o.LatestVersion = &v
}

func (o DependencyGraphResponse) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o DependencyGraphResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Uuid) {
		toSerialize["uuid"] = o.Uuid
	}
	if !IsNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !IsNil(o.Version) {
		toSerialize["version"] = o.Version
	}
	if !IsNil(o.Purl) {
		toSerialize["purl"] = o.Purl
	}
	if !IsNil(o.DirectDependencies) {
		toSerialize["directDependencies"] = o.DirectDependencies
	}
	if !IsNil(o.LatestVersion) {
		toSerialize["latestVersion"] = o.LatestVersion
	}
	return toSerialize, nil
}

type NullableDependencyGraphResponse struct {
	value *DependencyGraphResponse
	isSet bool
}

func (v NullableDependencyGraphResponse) Get() *DependencyGraphResponse {
	return v.value
}

func (v *NullableDependencyGraphResponse) Set(val *DependencyGraphResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableDependencyGraphResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableDependencyGraphResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDependencyGraphResponse(val *DependencyGraphResponse) *NullableDependencyGraphResponse {
	return &NullableDependencyGraphResponse{value: val, isSet: true}
}

func (v NullableDependencyGraphResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDependencyGraphResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


