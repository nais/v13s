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
	"time"
)

// checks if the RepositoryMetaComponent type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &RepositoryMetaComponent{}

// RepositoryMetaComponent struct for RepositoryMetaComponent
type RepositoryMetaComponent struct {
	RepositoryType string     `json:"repositoryType"`
	Namespace      *string    `json:"namespace,omitempty"`
	Name           string     `json:"name"`
	LatestVersion  string     `json:"latestVersion"`
	Published      *time.Time `json:"published,omitempty"`
	LastCheck      time.Time  `json:"lastCheck"`
}

type _RepositoryMetaComponent RepositoryMetaComponent

// NewRepositoryMetaComponent instantiates a new RepositoryMetaComponent object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewRepositoryMetaComponent(repositoryType string, name string, latestVersion string, lastCheck time.Time) *RepositoryMetaComponent {
	this := RepositoryMetaComponent{}
	this.RepositoryType = repositoryType
	this.Name = name
	this.LatestVersion = latestVersion
	this.LastCheck = lastCheck
	return &this
}

// NewRepositoryMetaComponentWithDefaults instantiates a new RepositoryMetaComponent object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewRepositoryMetaComponentWithDefaults() *RepositoryMetaComponent {
	this := RepositoryMetaComponent{}
	return &this
}

// GetRepositoryType returns the RepositoryType field value
func (o *RepositoryMetaComponent) GetRepositoryType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.RepositoryType
}

// GetRepositoryTypeOk returns a tuple with the RepositoryType field value
// and a boolean to check if the value has been set.
func (o *RepositoryMetaComponent) GetRepositoryTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.RepositoryType, true
}

// SetRepositoryType sets field value
func (o *RepositoryMetaComponent) SetRepositoryType(v string) {
	o.RepositoryType = v
}

// GetNamespace returns the Namespace field value if set, zero value otherwise.
func (o *RepositoryMetaComponent) GetNamespace() string {
	if o == nil || IsNil(o.Namespace) {
		var ret string
		return ret
	}
	return *o.Namespace
}

// GetNamespaceOk returns a tuple with the Namespace field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RepositoryMetaComponent) GetNamespaceOk() (*string, bool) {
	if o == nil || IsNil(o.Namespace) {
		return nil, false
	}
	return o.Namespace, true
}

// HasNamespace returns a boolean if a field has been set.
func (o *RepositoryMetaComponent) HasNamespace() bool {
	if o != nil && !IsNil(o.Namespace) {
		return true
	}

	return false
}

// SetNamespace gets a reference to the given string and assigns it to the Namespace field.
func (o *RepositoryMetaComponent) SetNamespace(v string) {
	o.Namespace = &v
}

// GetName returns the Name field value
func (o *RepositoryMetaComponent) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *RepositoryMetaComponent) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *RepositoryMetaComponent) SetName(v string) {
	o.Name = v
}

// GetLatestVersion returns the LatestVersion field value
func (o *RepositoryMetaComponent) GetLatestVersion() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.LatestVersion
}

// GetLatestVersionOk returns a tuple with the LatestVersion field value
// and a boolean to check if the value has been set.
func (o *RepositoryMetaComponent) GetLatestVersionOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.LatestVersion, true
}

// SetLatestVersion sets field value
func (o *RepositoryMetaComponent) SetLatestVersion(v string) {
	o.LatestVersion = v
}

// GetPublished returns the Published field value if set, zero value otherwise.
func (o *RepositoryMetaComponent) GetPublished() time.Time {
	if o == nil || IsNil(o.Published) {
		var ret time.Time
		return ret
	}
	return *o.Published
}

// GetPublishedOk returns a tuple with the Published field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *RepositoryMetaComponent) GetPublishedOk() (*time.Time, bool) {
	if o == nil || IsNil(o.Published) {
		return nil, false
	}
	return o.Published, true
}

// HasPublished returns a boolean if a field has been set.
func (o *RepositoryMetaComponent) HasPublished() bool {
	if o != nil && !IsNil(o.Published) {
		return true
	}

	return false
}

// SetPublished gets a reference to the given time.Time and assigns it to the Published field.
func (o *RepositoryMetaComponent) SetPublished(v time.Time) {
	o.Published = &v
}

// GetLastCheck returns the LastCheck field value
func (o *RepositoryMetaComponent) GetLastCheck() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.LastCheck
}

// GetLastCheckOk returns a tuple with the LastCheck field value
// and a boolean to check if the value has been set.
func (o *RepositoryMetaComponent) GetLastCheckOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.LastCheck, true
}

// SetLastCheck sets field value
func (o *RepositoryMetaComponent) SetLastCheck(v time.Time) {
	o.LastCheck = v
}

func (o RepositoryMetaComponent) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o RepositoryMetaComponent) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["repositoryType"] = o.RepositoryType
	if !IsNil(o.Namespace) {
		toSerialize["namespace"] = o.Namespace
	}
	toSerialize["name"] = o.Name
	toSerialize["latestVersion"] = o.LatestVersion
	if !IsNil(o.Published) {
		toSerialize["published"] = o.Published
	}
	toSerialize["lastCheck"] = o.LastCheck
	return toSerialize, nil
}

func (o *RepositoryMetaComponent) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"repositoryType",
		"name",
		"latestVersion",
		"lastCheck",
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

	varRepositoryMetaComponent := _RepositoryMetaComponent{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varRepositoryMetaComponent)

	if err != nil {
		return err
	}

	*o = RepositoryMetaComponent(varRepositoryMetaComponent)

	return err
}

type NullableRepositoryMetaComponent struct {
	value *RepositoryMetaComponent
	isSet bool
}

func (v NullableRepositoryMetaComponent) Get() *RepositoryMetaComponent {
	return v.value
}

func (v *NullableRepositoryMetaComponent) Set(val *RepositoryMetaComponent) {
	v.value = val
	v.isSet = true
}

func (v NullableRepositoryMetaComponent) IsSet() bool {
	return v.isSet
}

func (v *NullableRepositoryMetaComponent) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableRepositoryMetaComponent(val *RepositoryMetaComponent) *NullableRepositoryMetaComponent {
	return &NullableRepositoryMetaComponent{value: val, isSet: true}
}

func (v NullableRepositoryMetaComponent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableRepositoryMetaComponent) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
