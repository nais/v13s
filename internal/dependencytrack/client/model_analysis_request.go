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

// checks if the AnalysisRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AnalysisRequest{}

// AnalysisRequest struct for AnalysisRequest
type AnalysisRequest struct {
	Project               *string `json:"project,omitempty" validate:"regexp=^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
	Component             string  `json:"component" validate:"regexp=^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
	Vulnerability         string  `json:"vulnerability" validate:"regexp=^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
	AnalysisState         *string `json:"analysisState,omitempty"`
	AnalysisJustification *string `json:"analysisJustification,omitempty"`
	AnalysisResponse      *string `json:"analysisResponse,omitempty"`
	AnalysisDetails       *string `json:"analysisDetails,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}\\\\n\\\\r\\\\t]*$"`
	Comment               *string `json:"comment,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}\\\\n\\\\r\\\\t]*$"`
	Suppressed            *bool   `json:"suppressed,omitempty"`
}

type _AnalysisRequest AnalysisRequest

// NewAnalysisRequest instantiates a new AnalysisRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAnalysisRequest(component string, vulnerability string) *AnalysisRequest {
	this := AnalysisRequest{}
	this.Component = component
	this.Vulnerability = vulnerability
	return &this
}

// NewAnalysisRequestWithDefaults instantiates a new AnalysisRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAnalysisRequestWithDefaults() *AnalysisRequest {
	this := AnalysisRequest{}
	return &this
}

// GetProject returns the Project field value if set, zero value otherwise.
func (o *AnalysisRequest) GetProject() string {
	if o == nil || IsNil(o.Project) {
		var ret string
		return ret
	}
	return *o.Project
}

// GetProjectOk returns a tuple with the Project field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AnalysisRequest) GetProjectOk() (*string, bool) {
	if o == nil || IsNil(o.Project) {
		return nil, false
	}
	return o.Project, true
}

// HasProject returns a boolean if a field has been set.
func (o *AnalysisRequest) HasProject() bool {
	if o != nil && !IsNil(o.Project) {
		return true
	}

	return false
}

// SetProject gets a reference to the given string and assigns it to the Project field.
func (o *AnalysisRequest) SetProject(v string) {
	o.Project = &v
}

// GetComponent returns the Component field value
func (o *AnalysisRequest) GetComponent() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Component
}

// GetComponentOk returns a tuple with the Component field value
// and a boolean to check if the value has been set.
func (o *AnalysisRequest) GetComponentOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Component, true
}

// SetComponent sets field value
func (o *AnalysisRequest) SetComponent(v string) {
	o.Component = v
}

// GetVulnerability returns the Vulnerability field value
func (o *AnalysisRequest) GetVulnerability() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Vulnerability
}

// GetVulnerabilityOk returns a tuple with the Vulnerability field value
// and a boolean to check if the value has been set.
func (o *AnalysisRequest) GetVulnerabilityOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Vulnerability, true
}

// SetVulnerability sets field value
func (o *AnalysisRequest) SetVulnerability(v string) {
	o.Vulnerability = v
}

// GetAnalysisState returns the AnalysisState field value if set, zero value otherwise.
func (o *AnalysisRequest) GetAnalysisState() string {
	if o == nil || IsNil(o.AnalysisState) {
		var ret string
		return ret
	}
	return *o.AnalysisState
}

// GetAnalysisStateOk returns a tuple with the AnalysisState field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AnalysisRequest) GetAnalysisStateOk() (*string, bool) {
	if o == nil || IsNil(o.AnalysisState) {
		return nil, false
	}
	return o.AnalysisState, true
}

// HasAnalysisState returns a boolean if a field has been set.
func (o *AnalysisRequest) HasAnalysisState() bool {
	if o != nil && !IsNil(o.AnalysisState) {
		return true
	}

	return false
}

// SetAnalysisState gets a reference to the given string and assigns it to the AnalysisState field.
func (o *AnalysisRequest) SetAnalysisState(v string) {
	o.AnalysisState = &v
}

// GetAnalysisJustification returns the AnalysisJustification field value if set, zero value otherwise.
func (o *AnalysisRequest) GetAnalysisJustification() string {
	if o == nil || IsNil(o.AnalysisJustification) {
		var ret string
		return ret
	}
	return *o.AnalysisJustification
}

// GetAnalysisJustificationOk returns a tuple with the AnalysisJustification field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AnalysisRequest) GetAnalysisJustificationOk() (*string, bool) {
	if o == nil || IsNil(o.AnalysisJustification) {
		return nil, false
	}
	return o.AnalysisJustification, true
}

// HasAnalysisJustification returns a boolean if a field has been set.
func (o *AnalysisRequest) HasAnalysisJustification() bool {
	if o != nil && !IsNil(o.AnalysisJustification) {
		return true
	}

	return false
}

// SetAnalysisJustification gets a reference to the given string and assigns it to the AnalysisJustification field.
func (o *AnalysisRequest) SetAnalysisJustification(v string) {
	o.AnalysisJustification = &v
}

// GetAnalysisResponse returns the AnalysisResponse field value if set, zero value otherwise.
func (o *AnalysisRequest) GetAnalysisResponse() string {
	if o == nil || IsNil(o.AnalysisResponse) {
		var ret string
		return ret
	}
	return *o.AnalysisResponse
}

// GetAnalysisResponseOk returns a tuple with the AnalysisResponse field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AnalysisRequest) GetAnalysisResponseOk() (*string, bool) {
	if o == nil || IsNil(o.AnalysisResponse) {
		return nil, false
	}
	return o.AnalysisResponse, true
}

// HasAnalysisResponse returns a boolean if a field has been set.
func (o *AnalysisRequest) HasAnalysisResponse() bool {
	if o != nil && !IsNil(o.AnalysisResponse) {
		return true
	}

	return false
}

// SetAnalysisResponse gets a reference to the given string and assigns it to the AnalysisResponse field.
func (o *AnalysisRequest) SetAnalysisResponse(v string) {
	o.AnalysisResponse = &v
}

// GetAnalysisDetails returns the AnalysisDetails field value if set, zero value otherwise.
func (o *AnalysisRequest) GetAnalysisDetails() string {
	if o == nil || IsNil(o.AnalysisDetails) {
		var ret string
		return ret
	}
	return *o.AnalysisDetails
}

// GetAnalysisDetailsOk returns a tuple with the AnalysisDetails field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AnalysisRequest) GetAnalysisDetailsOk() (*string, bool) {
	if o == nil || IsNil(o.AnalysisDetails) {
		return nil, false
	}
	return o.AnalysisDetails, true
}

// HasAnalysisDetails returns a boolean if a field has been set.
func (o *AnalysisRequest) HasAnalysisDetails() bool {
	if o != nil && !IsNil(o.AnalysisDetails) {
		return true
	}

	return false
}

// SetAnalysisDetails gets a reference to the given string and assigns it to the AnalysisDetails field.
func (o *AnalysisRequest) SetAnalysisDetails(v string) {
	o.AnalysisDetails = &v
}

// GetComment returns the Comment field value if set, zero value otherwise.
func (o *AnalysisRequest) GetComment() string {
	if o == nil || IsNil(o.Comment) {
		var ret string
		return ret
	}
	return *o.Comment
}

// GetCommentOk returns a tuple with the Comment field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AnalysisRequest) GetCommentOk() (*string, bool) {
	if o == nil || IsNil(o.Comment) {
		return nil, false
	}
	return o.Comment, true
}

// HasComment returns a boolean if a field has been set.
func (o *AnalysisRequest) HasComment() bool {
	if o != nil && !IsNil(o.Comment) {
		return true
	}

	return false
}

// SetComment gets a reference to the given string and assigns it to the Comment field.
func (o *AnalysisRequest) SetComment(v string) {
	o.Comment = &v
}

// GetSuppressed returns the Suppressed field value if set, zero value otherwise.
func (o *AnalysisRequest) GetSuppressed() bool {
	if o == nil || IsNil(o.Suppressed) {
		var ret bool
		return ret
	}
	return *o.Suppressed
}

// GetSuppressedOk returns a tuple with the Suppressed field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AnalysisRequest) GetSuppressedOk() (*bool, bool) {
	if o == nil || IsNil(o.Suppressed) {
		return nil, false
	}
	return o.Suppressed, true
}

// HasSuppressed returns a boolean if a field has been set.
func (o *AnalysisRequest) HasSuppressed() bool {
	if o != nil && !IsNil(o.Suppressed) {
		return true
	}

	return false
}

// SetSuppressed gets a reference to the given bool and assigns it to the Suppressed field.
func (o *AnalysisRequest) SetSuppressed(v bool) {
	o.Suppressed = &v
}

func (o AnalysisRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AnalysisRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Project) {
		toSerialize["project"] = o.Project
	}
	toSerialize["component"] = o.Component
	toSerialize["vulnerability"] = o.Vulnerability
	if !IsNil(o.AnalysisState) {
		toSerialize["analysisState"] = o.AnalysisState
	}
	if !IsNil(o.AnalysisJustification) {
		toSerialize["analysisJustification"] = o.AnalysisJustification
	}
	if !IsNil(o.AnalysisResponse) {
		toSerialize["analysisResponse"] = o.AnalysisResponse
	}
	if !IsNil(o.AnalysisDetails) {
		toSerialize["analysisDetails"] = o.AnalysisDetails
	}
	if !IsNil(o.Comment) {
		toSerialize["comment"] = o.Comment
	}
	if !IsNil(o.Suppressed) {
		toSerialize["suppressed"] = o.Suppressed
	}
	return toSerialize, nil
}

func (o *AnalysisRequest) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"component",
		"vulnerability",
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

	varAnalysisRequest := _AnalysisRequest{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varAnalysisRequest)

	if err != nil {
		return err
	}

	*o = AnalysisRequest(varAnalysisRequest)

	return err
}

type NullableAnalysisRequest struct {
	value *AnalysisRequest
	isSet bool
}

func (v NullableAnalysisRequest) Get() *AnalysisRequest {
	return v.value
}

func (v *NullableAnalysisRequest) Set(val *AnalysisRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableAnalysisRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableAnalysisRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAnalysisRequest(val *AnalysisRequest) *NullableAnalysisRequest {
	return &NullableAnalysisRequest{value: val, isSet: true}
}

func (v NullableAnalysisRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAnalysisRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
