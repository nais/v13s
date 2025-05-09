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

// checks if the MappedOidcGroupRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &MappedOidcGroupRequest{}

// MappedOidcGroupRequest struct for MappedOidcGroupRequest
type MappedOidcGroupRequest struct {
	Team *string `json:"team,omitempty" validate:"regexp=^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
	Group *string `json:"group,omitempty" validate:"regexp=^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
}

// NewMappedOidcGroupRequest instantiates a new MappedOidcGroupRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewMappedOidcGroupRequest() *MappedOidcGroupRequest {
	this := MappedOidcGroupRequest{}
	return &this
}

// NewMappedOidcGroupRequestWithDefaults instantiates a new MappedOidcGroupRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewMappedOidcGroupRequestWithDefaults() *MappedOidcGroupRequest {
	this := MappedOidcGroupRequest{}
	return &this
}

// GetTeam returns the Team field value if set, zero value otherwise.
func (o *MappedOidcGroupRequest) GetTeam() string {
	if o == nil || IsNil(o.Team) {
		var ret string
		return ret
	}
	return *o.Team
}

// GetTeamOk returns a tuple with the Team field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MappedOidcGroupRequest) GetTeamOk() (*string, bool) {
	if o == nil || IsNil(o.Team) {
		return nil, false
	}
	return o.Team, true
}

// HasTeam returns a boolean if a field has been set.
func (o *MappedOidcGroupRequest) HasTeam() bool {
	if o != nil && !IsNil(o.Team) {
		return true
	}

	return false
}

// SetTeam gets a reference to the given string and assigns it to the Team field.
func (o *MappedOidcGroupRequest) SetTeam(v string) {
	o.Team = &v
}

// GetGroup returns the Group field value if set, zero value otherwise.
func (o *MappedOidcGroupRequest) GetGroup() string {
	if o == nil || IsNil(o.Group) {
		var ret string
		return ret
	}
	return *o.Group
}

// GetGroupOk returns a tuple with the Group field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MappedOidcGroupRequest) GetGroupOk() (*string, bool) {
	if o == nil || IsNil(o.Group) {
		return nil, false
	}
	return o.Group, true
}

// HasGroup returns a boolean if a field has been set.
func (o *MappedOidcGroupRequest) HasGroup() bool {
	if o != nil && !IsNil(o.Group) {
		return true
	}

	return false
}

// SetGroup gets a reference to the given string and assigns it to the Group field.
func (o *MappedOidcGroupRequest) SetGroup(v string) {
	o.Group = &v
}

func (o MappedOidcGroupRequest) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o MappedOidcGroupRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Team) {
		toSerialize["team"] = o.Team
	}
	if !IsNil(o.Group) {
		toSerialize["group"] = o.Group
	}
	return toSerialize, nil
}

type NullableMappedOidcGroupRequest struct {
	value *MappedOidcGroupRequest
	isSet bool
}

func (v NullableMappedOidcGroupRequest) Get() *MappedOidcGroupRequest {
	return v.value
}

func (v *NullableMappedOidcGroupRequest) Set(val *MappedOidcGroupRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableMappedOidcGroupRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableMappedOidcGroupRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableMappedOidcGroupRequest(val *MappedOidcGroupRequest) *NullableMappedOidcGroupRequest {
	return &NullableMappedOidcGroupRequest{value: val, isSet: true}
}

func (v NullableMappedOidcGroupRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableMappedOidcGroupRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


