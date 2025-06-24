# TagListResponseItem

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Name of the tag | 
**ProjectCount** | **int64** | Number of projects assigned to this tag | 
**CollectionProjectCount** | **int64** | Number of collection projects assigned to this tag | 
**PolicyCount** | **int64** | Number of policies assigned to this tag | 
**NotificationRuleCount** | **int64** | Number of notification rules assigned to this tag | 

## Methods

### NewTagListResponseItem

`func NewTagListResponseItem(name string, projectCount int64, collectionProjectCount int64, policyCount int64, notificationRuleCount int64, ) *TagListResponseItem`

NewTagListResponseItem instantiates a new TagListResponseItem object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewTagListResponseItemWithDefaults

`func NewTagListResponseItemWithDefaults() *TagListResponseItem`

NewTagListResponseItemWithDefaults instantiates a new TagListResponseItem object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *TagListResponseItem) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *TagListResponseItem) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *TagListResponseItem) SetName(v string)`

SetName sets Name field to given value.


### GetProjectCount

`func (o *TagListResponseItem) GetProjectCount() int64`

GetProjectCount returns the ProjectCount field if non-nil, zero value otherwise.

### GetProjectCountOk

`func (o *TagListResponseItem) GetProjectCountOk() (*int64, bool)`

GetProjectCountOk returns a tuple with the ProjectCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProjectCount

`func (o *TagListResponseItem) SetProjectCount(v int64)`

SetProjectCount sets ProjectCount field to given value.


### GetCollectionProjectCount

`func (o *TagListResponseItem) GetCollectionProjectCount() int64`

GetCollectionProjectCount returns the CollectionProjectCount field if non-nil, zero value otherwise.

### GetCollectionProjectCountOk

`func (o *TagListResponseItem) GetCollectionProjectCountOk() (*int64, bool)`

GetCollectionProjectCountOk returns a tuple with the CollectionProjectCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCollectionProjectCount

`func (o *TagListResponseItem) SetCollectionProjectCount(v int64)`

SetCollectionProjectCount sets CollectionProjectCount field to given value.


### GetPolicyCount

`func (o *TagListResponseItem) GetPolicyCount() int64`

GetPolicyCount returns the PolicyCount field if non-nil, zero value otherwise.

### GetPolicyCountOk

`func (o *TagListResponseItem) GetPolicyCountOk() (*int64, bool)`

GetPolicyCountOk returns a tuple with the PolicyCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyCount

`func (o *TagListResponseItem) SetPolicyCount(v int64)`

SetPolicyCount sets PolicyCount field to given value.


### GetNotificationRuleCount

`func (o *TagListResponseItem) GetNotificationRuleCount() int64`

GetNotificationRuleCount returns the NotificationRuleCount field if non-nil, zero value otherwise.

### GetNotificationRuleCountOk

`func (o *TagListResponseItem) GetNotificationRuleCountOk() (*int64, bool)`

GetNotificationRuleCountOk returns a tuple with the NotificationRuleCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNotificationRuleCount

`func (o *TagListResponseItem) SetNotificationRuleCount(v int64)`

SetNotificationRuleCount sets NotificationRuleCount field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


