# OrganizationalEntity

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**Urls** | Pointer to **[]string** |  | [optional] 
**Contacts** | Pointer to [**[]OrganizationalContact**](OrganizationalContact.md) |  | [optional] 

## Methods

### NewOrganizationalEntity

`func NewOrganizationalEntity() *OrganizationalEntity`

NewOrganizationalEntity instantiates a new OrganizationalEntity object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewOrganizationalEntityWithDefaults

`func NewOrganizationalEntityWithDefaults() *OrganizationalEntity`

NewOrganizationalEntityWithDefaults instantiates a new OrganizationalEntity object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *OrganizationalEntity) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *OrganizationalEntity) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *OrganizationalEntity) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *OrganizationalEntity) HasName() bool`

HasName returns a boolean if a field has been set.

### GetUrls

`func (o *OrganizationalEntity) GetUrls() []string`

GetUrls returns the Urls field if non-nil, zero value otherwise.

### GetUrlsOk

`func (o *OrganizationalEntity) GetUrlsOk() (*[]string, bool)`

GetUrlsOk returns a tuple with the Urls field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUrls

`func (o *OrganizationalEntity) SetUrls(v []string)`

SetUrls sets Urls field to given value.

### HasUrls

`func (o *OrganizationalEntity) HasUrls() bool`

HasUrls returns a boolean if a field has been set.

### GetContacts

`func (o *OrganizationalEntity) GetContacts() []OrganizationalContact`

GetContacts returns the Contacts field if non-nil, zero value otherwise.

### GetContactsOk

`func (o *OrganizationalEntity) GetContactsOk() (*[]OrganizationalContact, bool)`

GetContactsOk returns a tuple with the Contacts field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetContacts

`func (o *OrganizationalEntity) SetContacts(v []OrganizationalContact)`

SetContacts sets Contacts field to given value.

### HasContacts

`func (o *OrganizationalEntity) HasContacts() bool`

HasContacts returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


