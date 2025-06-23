# ProjectProperty

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**GroupName** | Pointer to **string** |  | [optional] 
**PropertyName** | Pointer to **string** |  | [optional] 
**PropertyValue** | Pointer to **string** |  | [optional] 
**PropertyType** | **string** |  | 
**Description** | Pointer to **string** |  | [optional] 

## Methods

### NewProjectProperty

`func NewProjectProperty(propertyType string, ) *ProjectProperty`

NewProjectProperty instantiates a new ProjectProperty object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewProjectPropertyWithDefaults

`func NewProjectPropertyWithDefaults() *ProjectProperty`

NewProjectPropertyWithDefaults instantiates a new ProjectProperty object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetGroupName

`func (o *ProjectProperty) GetGroupName() string`

GetGroupName returns the GroupName field if non-nil, zero value otherwise.

### GetGroupNameOk

`func (o *ProjectProperty) GetGroupNameOk() (*string, bool)`

GetGroupNameOk returns a tuple with the GroupName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGroupName

`func (o *ProjectProperty) SetGroupName(v string)`

SetGroupName sets GroupName field to given value.

### HasGroupName

`func (o *ProjectProperty) HasGroupName() bool`

HasGroupName returns a boolean if a field has been set.

### GetPropertyName

`func (o *ProjectProperty) GetPropertyName() string`

GetPropertyName returns the PropertyName field if non-nil, zero value otherwise.

### GetPropertyNameOk

`func (o *ProjectProperty) GetPropertyNameOk() (*string, bool)`

GetPropertyNameOk returns a tuple with the PropertyName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPropertyName

`func (o *ProjectProperty) SetPropertyName(v string)`

SetPropertyName sets PropertyName field to given value.

### HasPropertyName

`func (o *ProjectProperty) HasPropertyName() bool`

HasPropertyName returns a boolean if a field has been set.

### GetPropertyValue

`func (o *ProjectProperty) GetPropertyValue() string`

GetPropertyValue returns the PropertyValue field if non-nil, zero value otherwise.

### GetPropertyValueOk

`func (o *ProjectProperty) GetPropertyValueOk() (*string, bool)`

GetPropertyValueOk returns a tuple with the PropertyValue field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPropertyValue

`func (o *ProjectProperty) SetPropertyValue(v string)`

SetPropertyValue sets PropertyValue field to given value.

### HasPropertyValue

`func (o *ProjectProperty) HasPropertyValue() bool`

HasPropertyValue returns a boolean if a field has been set.

### GetPropertyType

`func (o *ProjectProperty) GetPropertyType() string`

GetPropertyType returns the PropertyType field if non-nil, zero value otherwise.

### GetPropertyTypeOk

`func (o *ProjectProperty) GetPropertyTypeOk() (*string, bool)`

GetPropertyTypeOk returns a tuple with the PropertyType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPropertyType

`func (o *ProjectProperty) SetPropertyType(v string)`

SetPropertyType sets PropertyType field to given value.


### GetDescription

`func (o *ProjectProperty) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *ProjectProperty) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *ProjectProperty) SetDescription(v string)`

SetDescription sets Description field to given value.

### HasDescription

`func (o *ProjectProperty) HasDescription() bool`

HasDescription returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


