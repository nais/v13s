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

// checks if the Tag type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &Tag{}

// Tag struct for Tag
type Tag struct {
	Name *string `json:"name,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}]*$"`
}

// NewTag instantiates a new Tag object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewTag() *Tag {
	this := Tag{}
	return &this
}

// NewTagWithDefaults instantiates a new Tag object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewTagWithDefaults() *Tag {
	this := Tag{}
	return &this
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *Tag) GetName() string {
	if o == nil || IsNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Tag) GetNameOk() (*string, bool) {
	if o == nil || IsNil(o.Name) {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *Tag) HasName() bool {
	if o != nil && !IsNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *Tag) SetName(v string) {
	o.Name = &v
}

func (o Tag) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o Tag) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	return toSerialize, nil
}

type NullableTag struct {
	value *Tag
	isSet bool
}

func (v NullableTag) Get() *Tag {
	return v.value
}

func (v *NullableTag) Set(val *Tag) {
	v.value = val
	v.isSet = true
}

func (v NullableTag) IsSet() bool {
	return v.isSet
}

func (v *NullableTag) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTag(val *Tag) *NullableTag {
	return &NullableTag{value: val, isSet: true}
}

func (v NullableTag) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTag) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


