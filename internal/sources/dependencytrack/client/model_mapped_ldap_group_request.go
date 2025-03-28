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

// checks if the MappedLdapGroupRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &MappedLdapGroupRequest{}

// MappedLdapGroupRequest struct for MappedLdapGroupRequest
type MappedLdapGroupRequest struct {
	Team *string `json:"team,omitempty" validate:"regexp=^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
	Dn   *string `json:"dn,omitempty" validate:"regexp=^[\\\\p{IsWhite_Space}\\\\p{L}\\\\p{M}\\\\p{S}\\\\p{N}\\\\p{P}\\\\n\\\\r\\\\t]*$"`
}

// NewMappedLdapGroupRequest instantiates a new MappedLdapGroupRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewMappedLdapGroupRequest() *MappedLdapGroupRequest {
	this := MappedLdapGroupRequest{}
	return &this
}

// NewMappedLdapGroupRequestWithDefaults instantiates a new MappedLdapGroupRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewMappedLdapGroupRequestWithDefaults() *MappedLdapGroupRequest {
	this := MappedLdapGroupRequest{}
	return &this
}

// GetTeam returns the Team field value if set, zero value otherwise.
func (o *MappedLdapGroupRequest) GetTeam() string {
	if o == nil || IsNil(o.Team) {
		var ret string
		return ret
	}
	return *o.Team
}

// GetTeamOk returns a tuple with the Team field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MappedLdapGroupRequest) GetTeamOk() (*string, bool) {
	if o == nil || IsNil(o.Team) {
		return nil, false
	}
	return o.Team, true
}

// HasTeam returns a boolean if a field has been set.
func (o *MappedLdapGroupRequest) HasTeam() bool {
	if o != nil && !IsNil(o.Team) {
		return true
	}

	return false
}

// SetTeam gets a reference to the given string and assigns it to the Team field.
func (o *MappedLdapGroupRequest) SetTeam(v string) {
	o.Team = &v
}

// GetDn returns the Dn field value if set, zero value otherwise.
func (o *MappedLdapGroupRequest) GetDn() string {
	if o == nil || IsNil(o.Dn) {
		var ret string
		return ret
	}
	return *o.Dn
}

// GetDnOk returns a tuple with the Dn field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MappedLdapGroupRequest) GetDnOk() (*string, bool) {
	if o == nil || IsNil(o.Dn) {
		return nil, false
	}
	return o.Dn, true
}

// HasDn returns a boolean if a field has been set.
func (o *MappedLdapGroupRequest) HasDn() bool {
	if o != nil && !IsNil(o.Dn) {
		return true
	}

	return false
}

// SetDn gets a reference to the given string and assigns it to the Dn field.
func (o *MappedLdapGroupRequest) SetDn(v string) {
	o.Dn = &v
}

func (o MappedLdapGroupRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o MappedLdapGroupRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Team) {
		toSerialize["team"] = o.Team
	}
	if !IsNil(o.Dn) {
		toSerialize["dn"] = o.Dn
	}
	return toSerialize, nil
}

type NullableMappedLdapGroupRequest struct {
	value *MappedLdapGroupRequest
	isSet bool
}

func (v NullableMappedLdapGroupRequest) Get() *MappedLdapGroupRequest {
	return v.value
}

func (v *NullableMappedLdapGroupRequest) Set(val *MappedLdapGroupRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableMappedLdapGroupRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableMappedLdapGroupRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableMappedLdapGroupRequest(val *MappedLdapGroupRequest) *NullableMappedLdapGroupRequest {
	return &NullableMappedLdapGroupRequest{value: val, isSet: true}
}

func (v NullableMappedLdapGroupRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableMappedLdapGroupRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
