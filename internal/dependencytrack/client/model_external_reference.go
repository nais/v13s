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

// checks if the ExternalReference type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ExternalReference{}

// ExternalReference struct for ExternalReference
type ExternalReference struct {
	Type    *string `json:"type,omitempty"`
	Url     *string `json:"url,omitempty"`
	Comment *string `json:"comment,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
}

// NewExternalReference instantiates a new ExternalReference object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewExternalReference() *ExternalReference {
	this := ExternalReference{}
	return &this
}

// NewExternalReferenceWithDefaults instantiates a new ExternalReference object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewExternalReferenceWithDefaults() *ExternalReference {
	this := ExternalReference{}
	return &this
}

// GetType returns the Type field value if set, zero value otherwise.
func (o *ExternalReference) GetType() string {
	if o == nil || IsNil(o.Type) {
		var ret string
		return ret
	}
	return *o.Type
}

// GetTypeOk returns a tuple with the Type field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ExternalReference) GetTypeOk() (*string, bool) {
	if o == nil || IsNil(o.Type) {
		return nil, false
	}
	return o.Type, true
}

// HasType returns a boolean if a field has been set.
func (o *ExternalReference) HasType() bool {
	if o != nil && !IsNil(o.Type) {
		return true
	}

	return false
}

// SetType gets a reference to the given string and assigns it to the Type field.
func (o *ExternalReference) SetType(v string) {
	o.Type = &v
}

// GetUrl returns the Url field value if set, zero value otherwise.
func (o *ExternalReference) GetUrl() string {
	if o == nil || IsNil(o.Url) {
		var ret string
		return ret
	}
	return *o.Url
}

// GetUrlOk returns a tuple with the Url field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ExternalReference) GetUrlOk() (*string, bool) {
	if o == nil || IsNil(o.Url) {
		return nil, false
	}
	return o.Url, true
}

// HasUrl returns a boolean if a field has been set.
func (o *ExternalReference) HasUrl() bool {
	if o != nil && !IsNil(o.Url) {
		return true
	}

	return false
}

// SetUrl gets a reference to the given string and assigns it to the Url field.
func (o *ExternalReference) SetUrl(v string) {
	o.Url = &v
}

// GetComment returns the Comment field value if set, zero value otherwise.
func (o *ExternalReference) GetComment() string {
	if o == nil || IsNil(o.Comment) {
		var ret string
		return ret
	}
	return *o.Comment
}

// GetCommentOk returns a tuple with the Comment field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ExternalReference) GetCommentOk() (*string, bool) {
	if o == nil || IsNil(o.Comment) {
		return nil, false
	}
	return o.Comment, true
}

// HasComment returns a boolean if a field has been set.
func (o *ExternalReference) HasComment() bool {
	if o != nil && !IsNil(o.Comment) {
		return true
	}

	return false
}

// SetComment gets a reference to the given string and assigns it to the Comment field.
func (o *ExternalReference) SetComment(v string) {
	o.Comment = &v
}

func (o ExternalReference) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ExternalReference) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Type) {
		toSerialize["type"] = o.Type
	}
	if !IsNil(o.Url) {
		toSerialize["url"] = o.Url
	}
	if !IsNil(o.Comment) {
		toSerialize["comment"] = o.Comment
	}
	return toSerialize, nil
}

type NullableExternalReference struct {
	value *ExternalReference
	isSet bool
}

func (v NullableExternalReference) Get() *ExternalReference {
	return v.value
}

func (v *NullableExternalReference) Set(val *ExternalReference) {
	v.value = val
	v.isSet = true
}

func (v NullableExternalReference) IsSet() bool {
	return v.isSet
}

func (v *NullableExternalReference) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableExternalReference(val *ExternalReference) *NullableExternalReference {
	return &NullableExternalReference{value: val, isSet: true}
}

func (v NullableExternalReference) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableExternalReference) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}