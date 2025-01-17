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

// checks if the UserPrincipal type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UserPrincipal{}

// UserPrincipal struct for UserPrincipal
type UserPrincipal struct {
	Name        *string      `json:"name,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
	Id          *int64       `json:"id,omitempty"`
	Teams       []Team       `json:"teams,omitempty"`
	Username    *string      `json:"username,omitempty"`
	Email       *string      `json:"email,omitempty"`
}

// NewUserPrincipal instantiates a new UserPrincipal object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUserPrincipal() *UserPrincipal {
	this := UserPrincipal{}
	return &this
}

// NewUserPrincipalWithDefaults instantiates a new UserPrincipal object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUserPrincipalWithDefaults() *UserPrincipal {
	this := UserPrincipal{}
	return &this
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *UserPrincipal) GetName() string {
	if o == nil || IsNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserPrincipal) GetNameOk() (*string, bool) {
	if o == nil || IsNil(o.Name) {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *UserPrincipal) HasName() bool {
	if o != nil && !IsNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *UserPrincipal) SetName(v string) {
	o.Name = &v
}

// GetPermissions returns the Permissions field value if set, zero value otherwise.
func (o *UserPrincipal) GetPermissions() []Permission {
	if o == nil || IsNil(o.Permissions) {
		var ret []Permission
		return ret
	}
	return o.Permissions
}

// GetPermissionsOk returns a tuple with the Permissions field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserPrincipal) GetPermissionsOk() ([]Permission, bool) {
	if o == nil || IsNil(o.Permissions) {
		return nil, false
	}
	return o.Permissions, true
}

// HasPermissions returns a boolean if a field has been set.
func (o *UserPrincipal) HasPermissions() bool {
	if o != nil && !IsNil(o.Permissions) {
		return true
	}

	return false
}

// SetPermissions gets a reference to the given []Permission and assigns it to the Permissions field.
func (o *UserPrincipal) SetPermissions(v []Permission) {
	o.Permissions = v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *UserPrincipal) GetId() int64 {
	if o == nil || IsNil(o.Id) {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserPrincipal) GetIdOk() (*int64, bool) {
	if o == nil || IsNil(o.Id) {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *UserPrincipal) HasId() bool {
	if o != nil && !IsNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *UserPrincipal) SetId(v int64) {
	o.Id = &v
}

// GetTeams returns the Teams field value if set, zero value otherwise.
func (o *UserPrincipal) GetTeams() []Team {
	if o == nil || IsNil(o.Teams) {
		var ret []Team
		return ret
	}
	return o.Teams
}

// GetTeamsOk returns a tuple with the Teams field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserPrincipal) GetTeamsOk() ([]Team, bool) {
	if o == nil || IsNil(o.Teams) {
		return nil, false
	}
	return o.Teams, true
}

// HasTeams returns a boolean if a field has been set.
func (o *UserPrincipal) HasTeams() bool {
	if o != nil && !IsNil(o.Teams) {
		return true
	}

	return false
}

// SetTeams gets a reference to the given []Team and assigns it to the Teams field.
func (o *UserPrincipal) SetTeams(v []Team) {
	o.Teams = v
}

// GetUsername returns the Username field value if set, zero value otherwise.
func (o *UserPrincipal) GetUsername() string {
	if o == nil || IsNil(o.Username) {
		var ret string
		return ret
	}
	return *o.Username
}

// GetUsernameOk returns a tuple with the Username field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserPrincipal) GetUsernameOk() (*string, bool) {
	if o == nil || IsNil(o.Username) {
		return nil, false
	}
	return o.Username, true
}

// HasUsername returns a boolean if a field has been set.
func (o *UserPrincipal) HasUsername() bool {
	if o != nil && !IsNil(o.Username) {
		return true
	}

	return false
}

// SetUsername gets a reference to the given string and assigns it to the Username field.
func (o *UserPrincipal) SetUsername(v string) {
	o.Username = &v
}

// GetEmail returns the Email field value if set, zero value otherwise.
func (o *UserPrincipal) GetEmail() string {
	if o == nil || IsNil(o.Email) {
		var ret string
		return ret
	}
	return *o.Email
}

// GetEmailOk returns a tuple with the Email field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserPrincipal) GetEmailOk() (*string, bool) {
	if o == nil || IsNil(o.Email) {
		return nil, false
	}
	return o.Email, true
}

// HasEmail returns a boolean if a field has been set.
func (o *UserPrincipal) HasEmail() bool {
	if o != nil && !IsNil(o.Email) {
		return true
	}

	return false
}

// SetEmail gets a reference to the given string and assigns it to the Email field.
func (o *UserPrincipal) SetEmail(v string) {
	o.Email = &v
}

func (o UserPrincipal) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UserPrincipal) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !IsNil(o.Permissions) {
		toSerialize["permissions"] = o.Permissions
	}
	if !IsNil(o.Id) {
		toSerialize["id"] = o.Id
	}
	if !IsNil(o.Teams) {
		toSerialize["teams"] = o.Teams
	}
	if !IsNil(o.Username) {
		toSerialize["username"] = o.Username
	}
	if !IsNil(o.Email) {
		toSerialize["email"] = o.Email
	}
	return toSerialize, nil
}

type NullableUserPrincipal struct {
	value *UserPrincipal
	isSet bool
}

func (v NullableUserPrincipal) Get() *UserPrincipal {
	return v.value
}

func (v *NullableUserPrincipal) Set(val *UserPrincipal) {
	v.value = val
	v.isSet = true
}

func (v NullableUserPrincipal) IsSet() bool {
	return v.isSet
}

func (v *NullableUserPrincipal) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUserPrincipal(val *UserPrincipal) *NullableUserPrincipal {
	return &NullableUserPrincipal{value: val, isSet: true}
}

func (v NullableUserPrincipal) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUserPrincipal) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
