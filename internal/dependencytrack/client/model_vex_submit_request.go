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

// checks if the VexSubmitRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &VexSubmitRequest{}

// VexSubmitRequest struct for VexSubmitRequest
type VexSubmitRequest struct {
	Project        string  `json:"project" validate:"regexp=^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
	ProjectName    *string `json:"projectName,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
	ProjectVersion *string `json:"projectVersion,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
	Vex            string  `json:"vex" validate:"regexp=^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?$"`
}

type _VexSubmitRequest VexSubmitRequest

// NewVexSubmitRequest instantiates a new VexSubmitRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewVexSubmitRequest(project string, vex string) *VexSubmitRequest {
	this := VexSubmitRequest{}
	this.Project = project
	this.Vex = vex
	return &this
}

// NewVexSubmitRequestWithDefaults instantiates a new VexSubmitRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewVexSubmitRequestWithDefaults() *VexSubmitRequest {
	this := VexSubmitRequest{}
	return &this
}

// GetProject returns the Project field value
func (o *VexSubmitRequest) GetProject() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Project
}

// GetProjectOk returns a tuple with the Project field value
// and a boolean to check if the value has been set.
func (o *VexSubmitRequest) GetProjectOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Project, true
}

// SetProject sets field value
func (o *VexSubmitRequest) SetProject(v string) {
	o.Project = v
}

// GetProjectName returns the ProjectName field value if set, zero value otherwise.
func (o *VexSubmitRequest) GetProjectName() string {
	if o == nil || IsNil(o.ProjectName) {
		var ret string
		return ret
	}
	return *o.ProjectName
}

// GetProjectNameOk returns a tuple with the ProjectName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *VexSubmitRequest) GetProjectNameOk() (*string, bool) {
	if o == nil || IsNil(o.ProjectName) {
		return nil, false
	}
	return o.ProjectName, true
}

// HasProjectName returns a boolean if a field has been set.
func (o *VexSubmitRequest) HasProjectName() bool {
	if o != nil && !IsNil(o.ProjectName) {
		return true
	}

	return false
}

// SetProjectName gets a reference to the given string and assigns it to the ProjectName field.
func (o *VexSubmitRequest) SetProjectName(v string) {
	o.ProjectName = &v
}

// GetProjectVersion returns the ProjectVersion field value if set, zero value otherwise.
func (o *VexSubmitRequest) GetProjectVersion() string {
	if o == nil || IsNil(o.ProjectVersion) {
		var ret string
		return ret
	}
	return *o.ProjectVersion
}

// GetProjectVersionOk returns a tuple with the ProjectVersion field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *VexSubmitRequest) GetProjectVersionOk() (*string, bool) {
	if o == nil || IsNil(o.ProjectVersion) {
		return nil, false
	}
	return o.ProjectVersion, true
}

// HasProjectVersion returns a boolean if a field has been set.
func (o *VexSubmitRequest) HasProjectVersion() bool {
	if o != nil && !IsNil(o.ProjectVersion) {
		return true
	}

	return false
}

// SetProjectVersion gets a reference to the given string and assigns it to the ProjectVersion field.
func (o *VexSubmitRequest) SetProjectVersion(v string) {
	o.ProjectVersion = &v
}

// GetVex returns the Vex field value
func (o *VexSubmitRequest) GetVex() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Vex
}

// GetVexOk returns a tuple with the Vex field value
// and a boolean to check if the value has been set.
func (o *VexSubmitRequest) GetVexOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Vex, true
}

// SetVex sets field value
func (o *VexSubmitRequest) SetVex(v string) {
	o.Vex = v
}

func (o VexSubmitRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o VexSubmitRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["project"] = o.Project
	if !IsNil(o.ProjectName) {
		toSerialize["projectName"] = o.ProjectName
	}
	if !IsNil(o.ProjectVersion) {
		toSerialize["projectVersion"] = o.ProjectVersion
	}
	toSerialize["vex"] = o.Vex
	return toSerialize, nil
}

func (o *VexSubmitRequest) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"project",
		"vex",
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

	varVexSubmitRequest := _VexSubmitRequest{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varVexSubmitRequest)

	if err != nil {
		return err
	}

	*o = VexSubmitRequest(varVexSubmitRequest)

	return err
}

type NullableVexSubmitRequest struct {
	value *VexSubmitRequest
	isSet bool
}

func (v NullableVexSubmitRequest) Get() *VexSubmitRequest {
	return v.value
}

func (v *NullableVexSubmitRequest) Set(val *VexSubmitRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableVexSubmitRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableVexSubmitRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableVexSubmitRequest(val *VexSubmitRequest) *NullableVexSubmitRequest {
	return &NullableVexSubmitRequest{value: val, isSet: true}
}

func (v NullableVexSubmitRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableVexSubmitRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}