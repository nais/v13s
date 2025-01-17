# LicenseGroup

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**Licenses** | Pointer to [**[]License**](License.md) |  | [optional] 
**RiskWeight** | Pointer to **int32** |  | [optional] 
**Uuid** | **string** |  | 

## Methods

### NewLicenseGroup

`func NewLicenseGroup(uuid string, ) *LicenseGroup`

NewLicenseGroup instantiates a new LicenseGroup object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewLicenseGroupWithDefaults

`func NewLicenseGroupWithDefaults() *LicenseGroup`

NewLicenseGroupWithDefaults instantiates a new LicenseGroup object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *LicenseGroup) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *LicenseGroup) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *LicenseGroup) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *LicenseGroup) HasName() bool`

HasName returns a boolean if a field has been set.

### GetLicenses

`func (o *LicenseGroup) GetLicenses() []License`

GetLicenses returns the Licenses field if non-nil, zero value otherwise.

### GetLicensesOk

`func (o *LicenseGroup) GetLicensesOk() (*[]License, bool)`

GetLicensesOk returns a tuple with the Licenses field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLicenses

`func (o *LicenseGroup) SetLicenses(v []License)`

SetLicenses sets Licenses field to given value.

### HasLicenses

`func (o *LicenseGroup) HasLicenses() bool`

HasLicenses returns a boolean if a field has been set.

### GetRiskWeight

`func (o *LicenseGroup) GetRiskWeight() int32`

GetRiskWeight returns the RiskWeight field if non-nil, zero value otherwise.

### GetRiskWeightOk

`func (o *LicenseGroup) GetRiskWeightOk() (*int32, bool)`

GetRiskWeightOk returns a tuple with the RiskWeight field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRiskWeight

`func (o *LicenseGroup) SetRiskWeight(v int32)`

SetRiskWeight sets RiskWeight field to given value.

### HasRiskWeight

`func (o *LicenseGroup) HasRiskWeight() bool`

HasRiskWeight returns a boolean if a field has been set.

### GetUuid

`func (o *LicenseGroup) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *LicenseGroup) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *LicenseGroup) SetUuid(v string)`

SetUuid sets Uuid field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


