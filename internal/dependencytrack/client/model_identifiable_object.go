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

// checks if the IdentifiableObject type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &IdentifiableObject{}

// IdentifiableObject struct for IdentifiableObject
type IdentifiableObject struct {
	Uuid *string `json:"uuid,omitempty"`
}

// NewIdentifiableObject instantiates a new IdentifiableObject object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewIdentifiableObject() *IdentifiableObject {
	this := IdentifiableObject{}
	return &this
}

// NewIdentifiableObjectWithDefaults instantiates a new IdentifiableObject object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewIdentifiableObjectWithDefaults() *IdentifiableObject {
	this := IdentifiableObject{}
	return &this
}

// GetUuid returns the Uuid field value if set, zero value otherwise.
func (o *IdentifiableObject) GetUuid() string {
	if o == nil || IsNil(o.Uuid) {
		var ret string
		return ret
	}
	return *o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IdentifiableObject) GetUuidOk() (*string, bool) {
	if o == nil || IsNil(o.Uuid) {
		return nil, false
	}
	return o.Uuid, true
}

// HasUuid returns a boolean if a field has been set.
func (o *IdentifiableObject) HasUuid() bool {
	if o != nil && !IsNil(o.Uuid) {
		return true
	}

	return false
}

// SetUuid gets a reference to the given string and assigns it to the Uuid field.
func (o *IdentifiableObject) SetUuid(v string) {
	o.Uuid = &v
}

func (o IdentifiableObject) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o IdentifiableObject) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Uuid) {
		toSerialize["uuid"] = o.Uuid
	}
	return toSerialize, nil
}

type NullableIdentifiableObject struct {
	value *IdentifiableObject
	isSet bool
}

func (v NullableIdentifiableObject) Get() *IdentifiableObject {
	return v.value
}

func (v *NullableIdentifiableObject) Set(val *IdentifiableObject) {
	v.value = val
	v.isSet = true
}

func (v NullableIdentifiableObject) IsSet() bool {
	return v.isSet
}

func (v *NullableIdentifiableObject) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIdentifiableObject(val *IdentifiableObject) *NullableIdentifiableObject {
	return &NullableIdentifiableObject{value: val, isSet: true}
}

func (v NullableIdentifiableObject) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIdentifiableObject) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}