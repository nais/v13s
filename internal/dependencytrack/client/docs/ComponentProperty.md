# ComponentProperty

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**GroupName** | Pointer to **string** |  | [optional] 
**PropertyName** | Pointer to **string** |  | [optional] 
**PropertyValue** | Pointer to **string** |  | [optional] 
**PropertyType** | **string** |  | 
**Description** | Pointer to **string** |  | [optional] 
**Uuid** | **string** |  | 

## Methods

### NewComponentProperty

`func NewComponentProperty(propertyType string, uuid string, ) *ComponentProperty`

NewComponentProperty instantiates a new ComponentProperty object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewComponentPropertyWithDefaults

`func NewComponentPropertyWithDefaults() *ComponentProperty`

NewComponentPropertyWithDefaults instantiates a new ComponentProperty object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetGroupName

`func (o *ComponentProperty) GetGroupName() string`

GetGroupName returns the GroupName field if non-nil, zero value otherwise.

### GetGroupNameOk

`func (o *ComponentProperty) GetGroupNameOk() (*string, bool)`

GetGroupNameOk returns a tuple with the GroupName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGroupName

`func (o *ComponentProperty) SetGroupName(v string)`

SetGroupName sets GroupName field to given value.

### HasGroupName

`func (o *ComponentProperty) HasGroupName() bool`

HasGroupName returns a boolean if a field has been set.

### GetPropertyName

`func (o *ComponentProperty) GetPropertyName() string`

GetPropertyName returns the PropertyName field if non-nil, zero value otherwise.

### GetPropertyNameOk

`func (o *ComponentProperty) GetPropertyNameOk() (*string, bool)`

GetPropertyNameOk returns a tuple with the PropertyName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPropertyName

`func (o *ComponentProperty) SetPropertyName(v string)`

SetPropertyName sets PropertyName field to given value.

### HasPropertyName

`func (o *ComponentProperty) HasPropertyName() bool`

HasPropertyName returns a boolean if a field has been set.

### GetPropertyValue

`func (o *ComponentProperty) GetPropertyValue() string`

GetPropertyValue returns the PropertyValue field if non-nil, zero value otherwise.

### GetPropertyValueOk

`func (o *ComponentProperty) GetPropertyValueOk() (*string, bool)`

GetPropertyValueOk returns a tuple with the PropertyValue field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPropertyValue

`func (o *ComponentProperty) SetPropertyValue(v string)`

SetPropertyValue sets PropertyValue field to given value.

### HasPropertyValue

`func (o *ComponentProperty) HasPropertyValue() bool`

HasPropertyValue returns a boolean if a field has been set.

### GetPropertyType

`func (o *ComponentProperty) GetPropertyType() string`

GetPropertyType returns the PropertyType field if non-nil, zero value otherwise.

### GetPropertyTypeOk

`func (o *ComponentProperty) GetPropertyTypeOk() (*string, bool)`

GetPropertyTypeOk returns a tuple with the PropertyType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPropertyType

`func (o *ComponentProperty) SetPropertyType(v string)`

SetPropertyType sets PropertyType field to given value.


### GetDescription

`func (o *ComponentProperty) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *ComponentProperty) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *ComponentProperty) SetDescription(v string)`

SetDescription sets Description field to given value.

### HasDescription

`func (o *ComponentProperty) HasDescription() bool`

HasDescription returns a boolean if a field has been set.

### GetUuid

`func (o *ComponentProperty) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *ComponentProperty) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *ComponentProperty) SetUuid(v string)`

SetUuid sets Uuid field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


