# About

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Version** | Pointer to **string** |  | [optional] 
**Timestamp** | Pointer to **string** |  | [optional] 
**SystemUuid** | Pointer to **string** |  | [optional] 
**Uuid** | Pointer to **string** |  | [optional] 
**Application** | Pointer to **string** |  | [optional] 
**Framework** | Pointer to [**Framework**](Framework.md) |  | [optional] 

## Methods

### NewAbout

`func NewAbout() *About`

NewAbout instantiates a new About object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAboutWithDefaults

`func NewAboutWithDefaults() *About`

NewAboutWithDefaults instantiates a new About object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetVersion

`func (o *About) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *About) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *About) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *About) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### GetTimestamp

`func (o *About) GetTimestamp() string`

GetTimestamp returns the Timestamp field if non-nil, zero value otherwise.

### GetTimestampOk

`func (o *About) GetTimestampOk() (*string, bool)`

GetTimestampOk returns a tuple with the Timestamp field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTimestamp

`func (o *About) SetTimestamp(v string)`

SetTimestamp sets Timestamp field to given value.

### HasTimestamp

`func (o *About) HasTimestamp() bool`

HasTimestamp returns a boolean if a field has been set.

### GetSystemUuid

`func (o *About) GetSystemUuid() string`

GetSystemUuid returns the SystemUuid field if non-nil, zero value otherwise.

### GetSystemUuidOk

`func (o *About) GetSystemUuidOk() (*string, bool)`

GetSystemUuidOk returns a tuple with the SystemUuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSystemUuid

`func (o *About) SetSystemUuid(v string)`

SetSystemUuid sets SystemUuid field to given value.

### HasSystemUuid

`func (o *About) HasSystemUuid() bool`

HasSystemUuid returns a boolean if a field has been set.

### GetUuid

`func (o *About) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *About) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *About) SetUuid(v string)`

SetUuid sets Uuid field to given value.

### HasUuid

`func (o *About) HasUuid() bool`

HasUuid returns a boolean if a field has been set.

### GetApplication

`func (o *About) GetApplication() string`

GetApplication returns the Application field if non-nil, zero value otherwise.

### GetApplicationOk

`func (o *About) GetApplicationOk() (*string, bool)`

GetApplicationOk returns a tuple with the Application field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetApplication

`func (o *About) SetApplication(v string)`

SetApplication sets Application field to given value.

### HasApplication

`func (o *About) HasApplication() bool`

HasApplication returns a boolean if a field has been set.

### GetFramework

`func (o *About) GetFramework() Framework`

GetFramework returns the Framework field if non-nil, zero value otherwise.

### GetFrameworkOk

`func (o *About) GetFrameworkOk() (*Framework, bool)`

GetFrameworkOk returns a tuple with the Framework field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFramework

`func (o *About) SetFramework(v Framework)`

SetFramework sets Framework field to given value.

### HasFramework

`func (o *About) HasFramework() bool`

HasFramework returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


