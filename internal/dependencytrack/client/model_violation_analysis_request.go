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

// checks if the ViolationAnalysisRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ViolationAnalysisRequest{}

// ViolationAnalysisRequest struct for ViolationAnalysisRequest
type ViolationAnalysisRequest struct {
	Component       string  `json:"component" validate:"regexp=^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
	PolicyViolation string  `json:"policyViolation" validate:"regexp=^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
	Comment         *string `json:"comment,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}\\\\n\\\\r\\\\t]*$"`
	AnalysisState   *string `json:"analysisState,omitempty"`
	Suppressed      *bool   `json:"suppressed,omitempty"`
}

type _ViolationAnalysisRequest ViolationAnalysisRequest

// NewViolationAnalysisRequest instantiates a new ViolationAnalysisRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewViolationAnalysisRequest(component string, policyViolation string) *ViolationAnalysisRequest {
	this := ViolationAnalysisRequest{}
	this.Component = component
	this.PolicyViolation = policyViolation
	return &this
}

// NewViolationAnalysisRequestWithDefaults instantiates a new ViolationAnalysisRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewViolationAnalysisRequestWithDefaults() *ViolationAnalysisRequest {
	this := ViolationAnalysisRequest{}
	return &this
}

// GetComponent returns the Component field value
func (o *ViolationAnalysisRequest) GetComponent() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Component
}

// GetComponentOk returns a tuple with the Component field value
// and a boolean to check if the value has been set.
func (o *ViolationAnalysisRequest) GetComponentOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Component, true
}

// SetComponent sets field value
func (o *ViolationAnalysisRequest) SetComponent(v string) {
	o.Component = v
}

// GetPolicyViolation returns the PolicyViolation field value
func (o *ViolationAnalysisRequest) GetPolicyViolation() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.PolicyViolation
}

// GetPolicyViolationOk returns a tuple with the PolicyViolation field value
// and a boolean to check if the value has been set.
func (o *ViolationAnalysisRequest) GetPolicyViolationOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.PolicyViolation, true
}

// SetPolicyViolation sets field value
func (o *ViolationAnalysisRequest) SetPolicyViolation(v string) {
	o.PolicyViolation = v
}

// GetComment returns the Comment field value if set, zero value otherwise.
func (o *ViolationAnalysisRequest) GetComment() string {
	if o == nil || IsNil(o.Comment) {
		var ret string
		return ret
	}
	return *o.Comment
}

// GetCommentOk returns a tuple with the Comment field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ViolationAnalysisRequest) GetCommentOk() (*string, bool) {
	if o == nil || IsNil(o.Comment) {
		return nil, false
	}
	return o.Comment, true
}

// HasComment returns a boolean if a field has been set.
func (o *ViolationAnalysisRequest) HasComment() bool {
	if o != nil && !IsNil(o.Comment) {
		return true
	}

	return false
}

// SetComment gets a reference to the given string and assigns it to the Comment field.
func (o *ViolationAnalysisRequest) SetComment(v string) {
	o.Comment = &v
}

// GetAnalysisState returns the AnalysisState field value if set, zero value otherwise.
func (o *ViolationAnalysisRequest) GetAnalysisState() string {
	if o == nil || IsNil(o.AnalysisState) {
		var ret string
		return ret
	}
	return *o.AnalysisState
}

// GetAnalysisStateOk returns a tuple with the AnalysisState field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ViolationAnalysisRequest) GetAnalysisStateOk() (*string, bool) {
	if o == nil || IsNil(o.AnalysisState) {
		return nil, false
	}
	return o.AnalysisState, true
}

// HasAnalysisState returns a boolean if a field has been set.
func (o *ViolationAnalysisRequest) HasAnalysisState() bool {
	if o != nil && !IsNil(o.AnalysisState) {
		return true
	}

	return false
}

// SetAnalysisState gets a reference to the given string and assigns it to the AnalysisState field.
func (o *ViolationAnalysisRequest) SetAnalysisState(v string) {
	o.AnalysisState = &v
}

// GetSuppressed returns the Suppressed field value if set, zero value otherwise.
func (o *ViolationAnalysisRequest) GetSuppressed() bool {
	if o == nil || IsNil(o.Suppressed) {
		var ret bool
		return ret
	}
	return *o.Suppressed
}

// GetSuppressedOk returns a tuple with the Suppressed field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ViolationAnalysisRequest) GetSuppressedOk() (*bool, bool) {
	if o == nil || IsNil(o.Suppressed) {
		return nil, false
	}
	return o.Suppressed, true
}

// HasSuppressed returns a boolean if a field has been set.
func (o *ViolationAnalysisRequest) HasSuppressed() bool {
	if o != nil && !IsNil(o.Suppressed) {
		return true
	}

	return false
}

// SetSuppressed gets a reference to the given bool and assigns it to the Suppressed field.
func (o *ViolationAnalysisRequest) SetSuppressed(v bool) {
	o.Suppressed = &v
}

func (o ViolationAnalysisRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ViolationAnalysisRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["component"] = o.Component
	toSerialize["policyViolation"] = o.PolicyViolation
	if !IsNil(o.Comment) {
		toSerialize["comment"] = o.Comment
	}
	if !IsNil(o.AnalysisState) {
		toSerialize["analysisState"] = o.AnalysisState
	}
	if !IsNil(o.Suppressed) {
		toSerialize["suppressed"] = o.Suppressed
	}
	return toSerialize, nil
}

func (o *ViolationAnalysisRequest) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"component",
		"policyViolation",
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

	varViolationAnalysisRequest := _ViolationAnalysisRequest{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varViolationAnalysisRequest)

	if err != nil {
		return err
	}

	*o = ViolationAnalysisRequest(varViolationAnalysisRequest)

	return err
}

type NullableViolationAnalysisRequest struct {
	value *ViolationAnalysisRequest
	isSet bool
}

func (v NullableViolationAnalysisRequest) Get() *ViolationAnalysisRequest {
	return v.value
}

func (v *NullableViolationAnalysisRequest) Set(val *ViolationAnalysisRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableViolationAnalysisRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableViolationAnalysisRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableViolationAnalysisRequest(val *ViolationAnalysisRequest) *NullableViolationAnalysisRequest {
	return &NullableViolationAnalysisRequest{value: val, isSet: true}
}

func (v NullableViolationAnalysisRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableViolationAnalysisRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}