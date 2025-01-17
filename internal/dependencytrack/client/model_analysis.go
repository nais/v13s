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

// checks if the Analysis type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &Analysis{}

// Analysis struct for Analysis
type Analysis struct {
	AnalysisState         string            `json:"analysisState"`
	AnalysisJustification string            `json:"analysisJustification"`
	AnalysisResponse      string            `json:"analysisResponse"`
	AnalysisDetails       string            `json:"analysisDetails"`
	AnalysisComments      []AnalysisComment `json:"analysisComments,omitempty"`
	IsSuppressed          *bool             `json:"isSuppressed,omitempty"`
}

type _Analysis Analysis

// NewAnalysis instantiates a new Analysis object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAnalysis(analysisState string, analysisJustification string, analysisResponse string, analysisDetails string) *Analysis {
	this := Analysis{}
	this.AnalysisState = analysisState
	this.AnalysisJustification = analysisJustification
	this.AnalysisResponse = analysisResponse
	this.AnalysisDetails = analysisDetails
	return &this
}

// NewAnalysisWithDefaults instantiates a new Analysis object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAnalysisWithDefaults() *Analysis {
	this := Analysis{}
	return &this
}

// GetAnalysisState returns the AnalysisState field value
func (o *Analysis) GetAnalysisState() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.AnalysisState
}

// GetAnalysisStateOk returns a tuple with the AnalysisState field value
// and a boolean to check if the value has been set.
func (o *Analysis) GetAnalysisStateOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AnalysisState, true
}

// SetAnalysisState sets field value
func (o *Analysis) SetAnalysisState(v string) {
	o.AnalysisState = v
}

// GetAnalysisJustification returns the AnalysisJustification field value
func (o *Analysis) GetAnalysisJustification() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.AnalysisJustification
}

// GetAnalysisJustificationOk returns a tuple with the AnalysisJustification field value
// and a boolean to check if the value has been set.
func (o *Analysis) GetAnalysisJustificationOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AnalysisJustification, true
}

// SetAnalysisJustification sets field value
func (o *Analysis) SetAnalysisJustification(v string) {
	o.AnalysisJustification = v
}

// GetAnalysisResponse returns the AnalysisResponse field value
func (o *Analysis) GetAnalysisResponse() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.AnalysisResponse
}

// GetAnalysisResponseOk returns a tuple with the AnalysisResponse field value
// and a boolean to check if the value has been set.
func (o *Analysis) GetAnalysisResponseOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AnalysisResponse, true
}

// SetAnalysisResponse sets field value
func (o *Analysis) SetAnalysisResponse(v string) {
	o.AnalysisResponse = v
}

// GetAnalysisDetails returns the AnalysisDetails field value
func (o *Analysis) GetAnalysisDetails() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.AnalysisDetails
}

// GetAnalysisDetailsOk returns a tuple with the AnalysisDetails field value
// and a boolean to check if the value has been set.
func (o *Analysis) GetAnalysisDetailsOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AnalysisDetails, true
}

// SetAnalysisDetails sets field value
func (o *Analysis) SetAnalysisDetails(v string) {
	o.AnalysisDetails = v
}

// GetAnalysisComments returns the AnalysisComments field value if set, zero value otherwise.
func (o *Analysis) GetAnalysisComments() []AnalysisComment {
	if o == nil || IsNil(o.AnalysisComments) {
		var ret []AnalysisComment
		return ret
	}
	return o.AnalysisComments
}

// GetAnalysisCommentsOk returns a tuple with the AnalysisComments field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Analysis) GetAnalysisCommentsOk() ([]AnalysisComment, bool) {
	if o == nil || IsNil(o.AnalysisComments) {
		return nil, false
	}
	return o.AnalysisComments, true
}

// HasAnalysisComments returns a boolean if a field has been set.
func (o *Analysis) HasAnalysisComments() bool {
	if o != nil && !IsNil(o.AnalysisComments) {
		return true
	}

	return false
}

// SetAnalysisComments gets a reference to the given []AnalysisComment and assigns it to the AnalysisComments field.
func (o *Analysis) SetAnalysisComments(v []AnalysisComment) {
	o.AnalysisComments = v
}

// GetIsSuppressed returns the IsSuppressed field value if set, zero value otherwise.
func (o *Analysis) GetIsSuppressed() bool {
	if o == nil || IsNil(o.IsSuppressed) {
		var ret bool
		return ret
	}
	return *o.IsSuppressed
}

// GetIsSuppressedOk returns a tuple with the IsSuppressed field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Analysis) GetIsSuppressedOk() (*bool, bool) {
	if o == nil || IsNil(o.IsSuppressed) {
		return nil, false
	}
	return o.IsSuppressed, true
}

// HasIsSuppressed returns a boolean if a field has been set.
func (o *Analysis) HasIsSuppressed() bool {
	if o != nil && !IsNil(o.IsSuppressed) {
		return true
	}

	return false
}

// SetIsSuppressed gets a reference to the given bool and assigns it to the IsSuppressed field.
func (o *Analysis) SetIsSuppressed(v bool) {
	o.IsSuppressed = &v
}

func (o Analysis) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o Analysis) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["analysisState"] = o.AnalysisState
	toSerialize["analysisJustification"] = o.AnalysisJustification
	toSerialize["analysisResponse"] = o.AnalysisResponse
	toSerialize["analysisDetails"] = o.AnalysisDetails
	if !IsNil(o.AnalysisComments) {
		toSerialize["analysisComments"] = o.AnalysisComments
	}
	if !IsNil(o.IsSuppressed) {
		toSerialize["isSuppressed"] = o.IsSuppressed
	}
	return toSerialize, nil
}

func (o *Analysis) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"analysisState",
		"analysisJustification",
		"analysisResponse",
		"analysisDetails",
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

	varAnalysis := _Analysis{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varAnalysis)

	if err != nil {
		return err
	}

	*o = Analysis(varAnalysis)

	return err
}

type NullableAnalysis struct {
	value *Analysis
	isSet bool
}

func (v NullableAnalysis) Get() *Analysis {
	return v.value
}

func (v *NullableAnalysis) Set(val *Analysis) {
	v.value = val
	v.isSet = true
}

func (v NullableAnalysis) IsSet() bool {
	return v.isSet
}

func (v *NullableAnalysis) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAnalysis(val *Analysis) *NullableAnalysis {
	return &NullableAnalysis{value: val, isSet: true}
}

func (v NullableAnalysis) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAnalysis) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
