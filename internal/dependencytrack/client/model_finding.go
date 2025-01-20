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

// checks if the Finding type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &Finding{}

// Finding struct for Finding
type Finding struct {
	Component     map[string]interface{} `json:"component,omitempty"`
	Vulnerability map[string]interface{} `json:"vulnerability,omitempty"`
	Analysis      map[string]interface{} `json:"analysis,omitempty"`
	Attribution   map[string]interface{} `json:"attribution,omitempty"`
	Matrix        *string                `json:"matrix,omitempty"`
}

// NewFinding instantiates a new Finding object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFinding() *Finding {
	this := Finding{}
	return &this
}

// NewFindingWithDefaults instantiates a new Finding object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFindingWithDefaults() *Finding {
	this := Finding{}
	return &this
}

// GetComponent returns the Component field value if set, zero value otherwise.
func (o *Finding) GetComponent() map[string]interface{} {
	if o == nil || IsNil(o.Component) {
		var ret map[string]interface{}
		return ret
	}
	return o.Component
}

// GetComponentOk returns a tuple with the Component field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Finding) GetComponentOk() (map[string]interface{}, bool) {
	if o == nil || IsNil(o.Component) {
		return map[string]interface{}{}, false
	}
	return o.Component, true
}

// HasComponent returns a boolean if a field has been set.
func (o *Finding) HasComponent() bool {
	if o != nil && !IsNil(o.Component) {
		return true
	}

	return false
}

// SetComponent gets a reference to the given map[string]interface{} and assigns it to the Component field.
func (o *Finding) SetComponent(v map[string]interface{}) {
	o.Component = v
}

// GetVulnerability returns the Vulnerability field value if set, zero value otherwise.
func (o *Finding) GetVulnerability() map[string]interface{} {
	if o == nil || IsNil(o.Vulnerability) {
		var ret map[string]interface{}
		return ret
	}
	return o.Vulnerability
}

// GetVulnerabilityOk returns a tuple with the Vulnerability field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Finding) GetVulnerabilityOk() (map[string]interface{}, bool) {
	if o == nil || IsNil(o.Vulnerability) {
		return map[string]interface{}{}, false
	}
	return o.Vulnerability, true
}

// HasVulnerability returns a boolean if a field has been set.
func (o *Finding) HasVulnerability() bool {
	if o != nil && !IsNil(o.Vulnerability) {
		return true
	}

	return false
}

// SetVulnerability gets a reference to the given map[string]interface{} and assigns it to the Vulnerability field.
func (o *Finding) SetVulnerability(v map[string]interface{}) {
	o.Vulnerability = v
}

// GetAnalysis returns the Analysis field value if set, zero value otherwise.
func (o *Finding) GetAnalysis() map[string]interface{} {
	if o == nil || IsNil(o.Analysis) {
		var ret map[string]interface{}
		return ret
	}
	return o.Analysis
}

// GetAnalysisOk returns a tuple with the Analysis field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Finding) GetAnalysisOk() (map[string]interface{}, bool) {
	if o == nil || IsNil(o.Analysis) {
		return map[string]interface{}{}, false
	}
	return o.Analysis, true
}

// HasAnalysis returns a boolean if a field has been set.
func (o *Finding) HasAnalysis() bool {
	if o != nil && !IsNil(o.Analysis) {
		return true
	}

	return false
}

// SetAnalysis gets a reference to the given map[string]interface{} and assigns it to the Analysis field.
func (o *Finding) SetAnalysis(v map[string]interface{}) {
	o.Analysis = v
}

// GetAttribution returns the Attribution field value if set, zero value otherwise.
func (o *Finding) GetAttribution() map[string]interface{} {
	if o == nil || IsNil(o.Attribution) {
		var ret map[string]interface{}
		return ret
	}
	return o.Attribution
}

// GetAttributionOk returns a tuple with the Attribution field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Finding) GetAttributionOk() (map[string]interface{}, bool) {
	if o == nil || IsNil(o.Attribution) {
		return map[string]interface{}{}, false
	}
	return o.Attribution, true
}

// HasAttribution returns a boolean if a field has been set.
func (o *Finding) HasAttribution() bool {
	if o != nil && !IsNil(o.Attribution) {
		return true
	}

	return false
}

// SetAttribution gets a reference to the given map[string]interface{} and assigns it to the Attribution field.
func (o *Finding) SetAttribution(v map[string]interface{}) {
	o.Attribution = v
}

// GetMatrix returns the Matrix field value if set, zero value otherwise.
func (o *Finding) GetMatrix() string {
	if o == nil || IsNil(o.Matrix) {
		var ret string
		return ret
	}
	return *o.Matrix
}

// GetMatrixOk returns a tuple with the Matrix field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Finding) GetMatrixOk() (*string, bool) {
	if o == nil || IsNil(o.Matrix) {
		return nil, false
	}
	return o.Matrix, true
}

// HasMatrix returns a boolean if a field has been set.
func (o *Finding) HasMatrix() bool {
	if o != nil && !IsNil(o.Matrix) {
		return true
	}

	return false
}

// SetMatrix gets a reference to the given string and assigns it to the Matrix field.
func (o *Finding) SetMatrix(v string) {
	o.Matrix = &v
}

func (o Finding) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o Finding) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Component) {
		toSerialize["component"] = o.Component
	}
	if !IsNil(o.Vulnerability) {
		toSerialize["vulnerability"] = o.Vulnerability
	}
	if !IsNil(o.Analysis) {
		toSerialize["analysis"] = o.Analysis
	}
	if !IsNil(o.Attribution) {
		toSerialize["attribution"] = o.Attribution
	}
	if !IsNil(o.Matrix) {
		toSerialize["matrix"] = o.Matrix
	}
	return toSerialize, nil
}

type NullableFinding struct {
	value *Finding
	isSet bool
}

func (v NullableFinding) Get() *Finding {
	return v.value
}

func (v *NullableFinding) Set(val *Finding) {
	v.value = val
	v.isSet = true
}

func (v NullableFinding) IsSet() bool {
	return v.isSet
}

func (v *NullableFinding) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFinding(val *Finding) *NullableFinding {
	return &NullableFinding{value: val, isSet: true}
}

func (v NullableFinding) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFinding) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
