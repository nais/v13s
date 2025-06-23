# Repository

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Identifier** | Pointer to **string** |  | [optional] 
**Url** | Pointer to **string** |  | [optional] 
**ResolutionOrder** | **int32** |  | 
**Enabled** | **bool** |  | 
**Internal** | **bool** |  | 
**AuthenticationRequired** | Pointer to **bool** |  | [optional] 
**Username** | Pointer to **string** |  | [optional] 
**Uuid** | **string** |  | 
**Password** | Pointer to **string** |  | [optional] 

## Methods

### NewRepository

`func NewRepository(type_ string, resolutionOrder int32, enabled bool, internal bool, uuid string, ) *Repository`

NewRepository instantiates a new Repository object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewRepositoryWithDefaults

`func NewRepositoryWithDefaults() *Repository`

NewRepositoryWithDefaults instantiates a new Repository object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *Repository) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *Repository) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *Repository) SetType(v string)`

SetType sets Type field to given value.


### GetIdentifier

`func (o *Repository) GetIdentifier() string`

GetIdentifier returns the Identifier field if non-nil, zero value otherwise.

### GetIdentifierOk

`func (o *Repository) GetIdentifierOk() (*string, bool)`

GetIdentifierOk returns a tuple with the Identifier field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIdentifier

`func (o *Repository) SetIdentifier(v string)`

SetIdentifier sets Identifier field to given value.

### HasIdentifier

`func (o *Repository) HasIdentifier() bool`

HasIdentifier returns a boolean if a field has been set.

### GetUrl

`func (o *Repository) GetUrl() string`

GetUrl returns the Url field if non-nil, zero value otherwise.

### GetUrlOk

`func (o *Repository) GetUrlOk() (*string, bool)`

GetUrlOk returns a tuple with the Url field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUrl

`func (o *Repository) SetUrl(v string)`

SetUrl sets Url field to given value.

### HasUrl

`func (o *Repository) HasUrl() bool`

HasUrl returns a boolean if a field has been set.

### GetResolutionOrder

`func (o *Repository) GetResolutionOrder() int32`

GetResolutionOrder returns the ResolutionOrder field if non-nil, zero value otherwise.

### GetResolutionOrderOk

`func (o *Repository) GetResolutionOrderOk() (*int32, bool)`

GetResolutionOrderOk returns a tuple with the ResolutionOrder field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetResolutionOrder

`func (o *Repository) SetResolutionOrder(v int32)`

SetResolutionOrder sets ResolutionOrder field to given value.


### GetEnabled

`func (o *Repository) GetEnabled() bool`

GetEnabled returns the Enabled field if non-nil, zero value otherwise.

### GetEnabledOk

`func (o *Repository) GetEnabledOk() (*bool, bool)`

GetEnabledOk returns a tuple with the Enabled field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnabled

`func (o *Repository) SetEnabled(v bool)`

SetEnabled sets Enabled field to given value.


### GetInternal

`func (o *Repository) GetInternal() bool`

GetInternal returns the Internal field if non-nil, zero value otherwise.

### GetInternalOk

`func (o *Repository) GetInternalOk() (*bool, bool)`

GetInternalOk returns a tuple with the Internal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInternal

`func (o *Repository) SetInternal(v bool)`

SetInternal sets Internal field to given value.


### GetAuthenticationRequired

`func (o *Repository) GetAuthenticationRequired() bool`

GetAuthenticationRequired returns the AuthenticationRequired field if non-nil, zero value otherwise.

### GetAuthenticationRequiredOk

`func (o *Repository) GetAuthenticationRequiredOk() (*bool, bool)`

GetAuthenticationRequiredOk returns a tuple with the AuthenticationRequired field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthenticationRequired

`func (o *Repository) SetAuthenticationRequired(v bool)`

SetAuthenticationRequired sets AuthenticationRequired field to given value.

### HasAuthenticationRequired

`func (o *Repository) HasAuthenticationRequired() bool`

HasAuthenticationRequired returns a boolean if a field has been set.

### GetUsername

`func (o *Repository) GetUsername() string`

GetUsername returns the Username field if non-nil, zero value otherwise.

### GetUsernameOk

`func (o *Repository) GetUsernameOk() (*string, bool)`

GetUsernameOk returns a tuple with the Username field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUsername

`func (o *Repository) SetUsername(v string)`

SetUsername sets Username field to given value.

### HasUsername

`func (o *Repository) HasUsername() bool`

HasUsername returns a boolean if a field has been set.

### GetUuid

`func (o *Repository) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *Repository) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *Repository) SetUuid(v string)`

SetUuid sets Uuid field to given value.


### GetPassword

`func (o *Repository) GetPassword() string`

GetPassword returns the Password field if non-nil, zero value otherwise.

### GetPasswordOk

`func (o *Repository) GetPasswordOk() (*string, bool)`

GetPasswordOk returns a tuple with the Password field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassword

`func (o *Repository) SetPassword(v string)`

SetPassword sets Password field to given value.

### HasPassword

`func (o *Repository) HasPassword() bool`

HasPassword returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


