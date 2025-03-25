# ConfigProperty

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**GroupName** | Pointer to **string** |  | [optional] 
**PropertyName** | Pointer to **string** |  | [optional] 
**PropertyValue** | Pointer to **string** |  | [optional] 
**PropertyType** | **string** |  | 
**Description** | Pointer to **string** |  | [optional] 

## Methods

### NewConfigProperty

`func NewConfigProperty(propertyType string, ) *ConfigProperty`

NewConfigProperty instantiates a new ConfigProperty object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewConfigPropertyWithDefaults

`func NewConfigPropertyWithDefaults() *ConfigProperty`

NewConfigPropertyWithDefaults instantiates a new ConfigProperty object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetGroupName

`func (o *ConfigProperty) GetGroupName() string`

GetGroupName returns the GroupName field if non-nil, zero value otherwise.

### GetGroupNameOk

`func (o *ConfigProperty) GetGroupNameOk() (*string, bool)`

GetGroupNameOk returns a tuple with the GroupName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGroupName

`func (o *ConfigProperty) SetGroupName(v string)`

SetGroupName sets GroupName field to given value.

### HasGroupName

`func (o *ConfigProperty) HasGroupName() bool`

HasGroupName returns a boolean if a field has been set.

### GetPropertyName

`func (o *ConfigProperty) GetPropertyName() string`

GetPropertyName returns the PropertyName field if non-nil, zero value otherwise.

### GetPropertyNameOk

`func (o *ConfigProperty) GetPropertyNameOk() (*string, bool)`

GetPropertyNameOk returns a tuple with the PropertyName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPropertyName

`func (o *ConfigProperty) SetPropertyName(v string)`

SetPropertyName sets PropertyName field to given value.

### HasPropertyName

`func (o *ConfigProperty) HasPropertyName() bool`

HasPropertyName returns a boolean if a field has been set.

### GetPropertyValue

`func (o *ConfigProperty) GetPropertyValue() string`

GetPropertyValue returns the PropertyValue field if non-nil, zero value otherwise.

### GetPropertyValueOk

`func (o *ConfigProperty) GetPropertyValueOk() (*string, bool)`

GetPropertyValueOk returns a tuple with the PropertyValue field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPropertyValue

`func (o *ConfigProperty) SetPropertyValue(v string)`

SetPropertyValue sets PropertyValue field to given value.

### HasPropertyValue

`func (o *ConfigProperty) HasPropertyValue() bool`

HasPropertyValue returns a boolean if a field has been set.

### GetPropertyType

`func (o *ConfigProperty) GetPropertyType() string`

GetPropertyType returns the PropertyType field if non-nil, zero value otherwise.

### GetPropertyTypeOk

`func (o *ConfigProperty) GetPropertyTypeOk() (*string, bool)`

GetPropertyTypeOk returns a tuple with the PropertyType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPropertyType

`func (o *ConfigProperty) SetPropertyType(v string)`

SetPropertyType sets PropertyType field to given value.


### GetDescription

`func (o *ConfigProperty) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *ConfigProperty) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *ConfigProperty) SetDescription(v string)`

SetDescription sets Description field to given value.

### HasDescription

`func (o *ConfigProperty) HasDescription() bool`

HasDescription returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


