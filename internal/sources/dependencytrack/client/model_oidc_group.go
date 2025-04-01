/*
Dependency-Track API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 4.11.7
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
	"bytes"
	"fmt"
)

// checks if the OidcGroup type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &OidcGroup{}

// OidcGroup struct for OidcGroup
type OidcGroup struct {
	Uuid string `json:"uuid"`
	Name *string `json:"name,omitempty" validate:"regexp=[\\\\P{Cc}]+"`
}

type _OidcGroup OidcGroup

// NewOidcGroup instantiates a new OidcGroup object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewOidcGroup(uuid string) *OidcGroup {
	this := OidcGroup{}
	this.Uuid = uuid
	return &this
}

// NewOidcGroupWithDefaults instantiates a new OidcGroup object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewOidcGroupWithDefaults() *OidcGroup {
	this := OidcGroup{}
	return &this
}

// GetUuid returns the Uuid field value
func (o *OidcGroup) GetUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value
// and a boolean to check if the value has been set.
func (o *OidcGroup) GetUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Uuid, true
}

// SetUuid sets field value
func (o *OidcGroup) SetUuid(v string) {
	o.Uuid = v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *OidcGroup) GetName() string {
	if o == nil || IsNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *OidcGroup) GetNameOk() (*string, bool) {
	if o == nil || IsNil(o.Name) {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *OidcGroup) HasName() bool {
	if o != nil && !IsNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *OidcGroup) SetName(v string) {
	o.Name = &v
}

func (o OidcGroup) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o OidcGroup) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["uuid"] = o.Uuid
	if !IsNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	return toSerialize, nil
}

func (o *OidcGroup) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"uuid",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(data, &allProperties)

	if err != nil {
		return err;
	}

	for _, requiredProperty := range(requiredProperties) {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varOidcGroup := _OidcGroup{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varOidcGroup)

	if err != nil {
		return err
	}

	*o = OidcGroup(varOidcGroup)

	return err
}

type NullableOidcGroup struct {
	value *OidcGroup
	isSet bool
}

func (v NullableOidcGroup) Get() *OidcGroup {
	return v.value
}

func (v *NullableOidcGroup) Set(val *OidcGroup) {
	v.value = val
	v.isSet = true
}

func (v NullableOidcGroup) IsSet() bool {
	return v.isSet
}

func (v *NullableOidcGroup) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableOidcGroup(val *OidcGroup) *NullableOidcGroup {
	return &NullableOidcGroup{value: val, isSet: true}
}

func (v NullableOidcGroup) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableOidcGroup) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


