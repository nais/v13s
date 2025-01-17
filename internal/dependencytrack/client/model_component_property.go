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

// checks if the ComponentProperty type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ComponentProperty{}

// ComponentProperty struct for ComponentProperty
type ComponentProperty struct {
	GroupName     *string `json:"groupName,omitempty" validate:"regexp=\\\\P{Cc}+"`
	PropertyName  *string `json:"propertyName,omitempty" validate:"regexp=\\\\P{Cc}+"`
	PropertyValue *string `json:"propertyValue,omitempty" validate:"regexp=\\\\P{Cc}+"`
	PropertyType  string  `json:"propertyType"`
	Description   *string `json:"description,omitempty" validate:"regexp=\\\\P{Cc}+"`
	Uuid          string  `json:"uuid"`
}

type _ComponentProperty ComponentProperty

// NewComponentProperty instantiates a new ComponentProperty object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewComponentProperty(propertyType string, uuid string) *ComponentProperty {
	this := ComponentProperty{}
	this.PropertyType = propertyType
	this.Uuid = uuid
	return &this
}

// NewComponentPropertyWithDefaults instantiates a new ComponentProperty object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewComponentPropertyWithDefaults() *ComponentProperty {
	this := ComponentProperty{}
	return &this
}

// GetGroupName returns the GroupName field value if set, zero value otherwise.
func (o *ComponentProperty) GetGroupName() string {
	if o == nil || IsNil(o.GroupName) {
		var ret string
		return ret
	}
	return *o.GroupName
}

// GetGroupNameOk returns a tuple with the GroupName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComponentProperty) GetGroupNameOk() (*string, bool) {
	if o == nil || IsNil(o.GroupName) {
		return nil, false
	}
	return o.GroupName, true
}

// HasGroupName returns a boolean if a field has been set.
func (o *ComponentProperty) HasGroupName() bool {
	if o != nil && !IsNil(o.GroupName) {
		return true
	}

	return false
}

// SetGroupName gets a reference to the given string and assigns it to the GroupName field.
func (o *ComponentProperty) SetGroupName(v string) {
	o.GroupName = &v
}

// GetPropertyName returns the PropertyName field value if set, zero value otherwise.
func (o *ComponentProperty) GetPropertyName() string {
	if o == nil || IsNil(o.PropertyName) {
		var ret string
		return ret
	}
	return *o.PropertyName
}

// GetPropertyNameOk returns a tuple with the PropertyName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComponentProperty) GetPropertyNameOk() (*string, bool) {
	if o == nil || IsNil(o.PropertyName) {
		return nil, false
	}
	return o.PropertyName, true
}

// HasPropertyName returns a boolean if a field has been set.
func (o *ComponentProperty) HasPropertyName() bool {
	if o != nil && !IsNil(o.PropertyName) {
		return true
	}

	return false
}

// SetPropertyName gets a reference to the given string and assigns it to the PropertyName field.
func (o *ComponentProperty) SetPropertyName(v string) {
	o.PropertyName = &v
}

// GetPropertyValue returns the PropertyValue field value if set, zero value otherwise.
func (o *ComponentProperty) GetPropertyValue() string {
	if o == nil || IsNil(o.PropertyValue) {
		var ret string
		return ret
	}
	return *o.PropertyValue
}

// GetPropertyValueOk returns a tuple with the PropertyValue field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComponentProperty) GetPropertyValueOk() (*string, bool) {
	if o == nil || IsNil(o.PropertyValue) {
		return nil, false
	}
	return o.PropertyValue, true
}

// HasPropertyValue returns a boolean if a field has been set.
func (o *ComponentProperty) HasPropertyValue() bool {
	if o != nil && !IsNil(o.PropertyValue) {
		return true
	}

	return false
}

// SetPropertyValue gets a reference to the given string and assigns it to the PropertyValue field.
func (o *ComponentProperty) SetPropertyValue(v string) {
	o.PropertyValue = &v
}

// GetPropertyType returns the PropertyType field value
func (o *ComponentProperty) GetPropertyType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.PropertyType
}

// GetPropertyTypeOk returns a tuple with the PropertyType field value
// and a boolean to check if the value has been set.
func (o *ComponentProperty) GetPropertyTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.PropertyType, true
}

// SetPropertyType sets field value
func (o *ComponentProperty) SetPropertyType(v string) {
	o.PropertyType = v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *ComponentProperty) GetDescription() string {
	if o == nil || IsNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComponentProperty) GetDescriptionOk() (*string, bool) {
	if o == nil || IsNil(o.Description) {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *ComponentProperty) HasDescription() bool {
	if o != nil && !IsNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *ComponentProperty) SetDescription(v string) {
	o.Description = &v
}

// GetUuid returns the Uuid field value
func (o *ComponentProperty) GetUuid() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Uuid
}

// GetUuidOk returns a tuple with the Uuid field value
// and a boolean to check if the value has been set.
func (o *ComponentProperty) GetUuidOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Uuid, true
}

// SetUuid sets field value
func (o *ComponentProperty) SetUuid(v string) {
	o.Uuid = v
}

func (o ComponentProperty) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ComponentProperty) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.GroupName) {
		toSerialize["groupName"] = o.GroupName
	}
	if !IsNil(o.PropertyName) {
		toSerialize["propertyName"] = o.PropertyName
	}
	if !IsNil(o.PropertyValue) {
		toSerialize["propertyValue"] = o.PropertyValue
	}
	toSerialize["propertyType"] = o.PropertyType
	if !IsNil(o.Description) {
		toSerialize["description"] = o.Description
	}
	toSerialize["uuid"] = o.Uuid
	return toSerialize, nil
}

func (o *ComponentProperty) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"propertyType",
		"uuid",
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

	varComponentProperty := _ComponentProperty{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varComponentProperty)

	if err != nil {
		return err
	}

	*o = ComponentProperty(varComponentProperty)

	return err
}

type NullableComponentProperty struct {
	value *ComponentProperty
	isSet bool
}

func (v NullableComponentProperty) Get() *ComponentProperty {
	return v.value
}

func (v *NullableComponentProperty) Set(val *ComponentProperty) {
	v.value = val
	v.isSet = true
}

func (v NullableComponentProperty) IsSet() bool {
	return v.isSet
}

func (v *NullableComponentProperty) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableComponentProperty(val *ComponentProperty) *NullableComponentProperty {
	return &NullableComponentProperty{value: val, isSet: true}
}

func (v NullableComponentProperty) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableComponentProperty) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
