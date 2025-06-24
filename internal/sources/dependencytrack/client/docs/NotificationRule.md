# NotificationRule

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** |  | 
**Enabled** | Pointer to **bool** |  | [optional] 
**NotifyChildren** | Pointer to **bool** |  | [optional] 
**LogSuccessfulPublish** | Pointer to **bool** |  | [optional] 
**Scope** | **string** |  | 
**NotificationLevel** | Pointer to **string** |  | [optional] 
**Projects** | Pointer to [**[]Project**](Project.md) |  | [optional] 
**Tags** | Pointer to [**[]Tag**](Tag.md) |  | [optional] 
**Teams** | Pointer to [**[]Team**](Team.md) |  | [optional] 
**NotifyOn** | Pointer to **[]string** |  | [optional] 
**Message** | Pointer to **string** |  | [optional] 
**Publisher** | Pointer to [**NotificationPublisher**](NotificationPublisher.md) |  | [optional] 
**PublisherConfig** | Pointer to **string** |  | [optional] 
**TriggerType** | **string** |  | [readonly] 
**ScheduleLastTriggeredAt** | Pointer to **int64** | When the schedule last triggered, as UNIX epoch timestamp in milliseconds | [optional] [readonly] 
**ScheduleNextTriggerAt** | Pointer to **int64** | When the schedule triggers next, as UNIX epoch timestamp in milliseconds | [optional] [readonly] 
**ScheduleCron** | Pointer to **string** | Schedule of this rule as cron expression. Must not be set for rules with trigger type EVENT. | [optional] 
**ScheduleSkipUnchanged** | Pointer to **bool** | Whether to skip emitting a scheduled notification if it doesn&#39;t contain any changes since its last emission. Must not be set for rules with trigger type EVENT. | [optional] 
**Uuid** | **string** |  | 

## Methods

### NewNotificationRule

`func NewNotificationRule(name string, scope string, triggerType string, uuid string, ) *NotificationRule`

NewNotificationRule instantiates a new NotificationRule object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewNotificationRuleWithDefaults

`func NewNotificationRuleWithDefaults() *NotificationRule`

NewNotificationRuleWithDefaults instantiates a new NotificationRule object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *NotificationRule) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *NotificationRule) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *NotificationRule) SetName(v string)`

SetName sets Name field to given value.


### GetEnabled

`func (o *NotificationRule) GetEnabled() bool`

GetEnabled returns the Enabled field if non-nil, zero value otherwise.

### GetEnabledOk

`func (o *NotificationRule) GetEnabledOk() (*bool, bool)`

GetEnabledOk returns a tuple with the Enabled field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEnabled

`func (o *NotificationRule) SetEnabled(v bool)`

SetEnabled sets Enabled field to given value.

### HasEnabled

`func (o *NotificationRule) HasEnabled() bool`

HasEnabled returns a boolean if a field has been set.

### GetNotifyChildren

`func (o *NotificationRule) GetNotifyChildren() bool`

GetNotifyChildren returns the NotifyChildren field if non-nil, zero value otherwise.

### GetNotifyChildrenOk

`func (o *NotificationRule) GetNotifyChildrenOk() (*bool, bool)`

GetNotifyChildrenOk returns a tuple with the NotifyChildren field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNotifyChildren

`func (o *NotificationRule) SetNotifyChildren(v bool)`

SetNotifyChildren sets NotifyChildren field to given value.

### HasNotifyChildren

`func (o *NotificationRule) HasNotifyChildren() bool`

HasNotifyChildren returns a boolean if a field has been set.

### GetLogSuccessfulPublish

`func (o *NotificationRule) GetLogSuccessfulPublish() bool`

GetLogSuccessfulPublish returns the LogSuccessfulPublish field if non-nil, zero value otherwise.

### GetLogSuccessfulPublishOk

`func (o *NotificationRule) GetLogSuccessfulPublishOk() (*bool, bool)`

GetLogSuccessfulPublishOk returns a tuple with the LogSuccessfulPublish field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLogSuccessfulPublish

`func (o *NotificationRule) SetLogSuccessfulPublish(v bool)`

SetLogSuccessfulPublish sets LogSuccessfulPublish field to given value.

### HasLogSuccessfulPublish

`func (o *NotificationRule) HasLogSuccessfulPublish() bool`

HasLogSuccessfulPublish returns a boolean if a field has been set.

### GetScope

`func (o *NotificationRule) GetScope() string`

GetScope returns the Scope field if non-nil, zero value otherwise.

### GetScopeOk

`func (o *NotificationRule) GetScopeOk() (*string, bool)`

GetScopeOk returns a tuple with the Scope field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScope

`func (o *NotificationRule) SetScope(v string)`

SetScope sets Scope field to given value.


### GetNotificationLevel

`func (o *NotificationRule) GetNotificationLevel() string`

GetNotificationLevel returns the NotificationLevel field if non-nil, zero value otherwise.

### GetNotificationLevelOk

`func (o *NotificationRule) GetNotificationLevelOk() (*string, bool)`

GetNotificationLevelOk returns a tuple with the NotificationLevel field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNotificationLevel

`func (o *NotificationRule) SetNotificationLevel(v string)`

SetNotificationLevel sets NotificationLevel field to given value.

### HasNotificationLevel

`func (o *NotificationRule) HasNotificationLevel() bool`

HasNotificationLevel returns a boolean if a field has been set.

### GetProjects

`func (o *NotificationRule) GetProjects() []Project`

GetProjects returns the Projects field if non-nil, zero value otherwise.

### GetProjectsOk

`func (o *NotificationRule) GetProjectsOk() (*[]Project, bool)`

GetProjectsOk returns a tuple with the Projects field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProjects

`func (o *NotificationRule) SetProjects(v []Project)`

SetProjects sets Projects field to given value.

### HasProjects

`func (o *NotificationRule) HasProjects() bool`

HasProjects returns a boolean if a field has been set.

### GetTags

`func (o *NotificationRule) GetTags() []Tag`

GetTags returns the Tags field if non-nil, zero value otherwise.

### GetTagsOk

`func (o *NotificationRule) GetTagsOk() (*[]Tag, bool)`

GetTagsOk returns a tuple with the Tags field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTags

`func (o *NotificationRule) SetTags(v []Tag)`

SetTags sets Tags field to given value.

### HasTags

`func (o *NotificationRule) HasTags() bool`

HasTags returns a boolean if a field has been set.

### GetTeams

`func (o *NotificationRule) GetTeams() []Team`

GetTeams returns the Teams field if non-nil, zero value otherwise.

### GetTeamsOk

`func (o *NotificationRule) GetTeamsOk() (*[]Team, bool)`

GetTeamsOk returns a tuple with the Teams field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTeams

`func (o *NotificationRule) SetTeams(v []Team)`

SetTeams sets Teams field to given value.

### HasTeams

`func (o *NotificationRule) HasTeams() bool`

HasTeams returns a boolean if a field has been set.

### GetNotifyOn

`func (o *NotificationRule) GetNotifyOn() []string`

GetNotifyOn returns the NotifyOn field if non-nil, zero value otherwise.

### GetNotifyOnOk

`func (o *NotificationRule) GetNotifyOnOk() (*[]string, bool)`

GetNotifyOnOk returns a tuple with the NotifyOn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNotifyOn

`func (o *NotificationRule) SetNotifyOn(v []string)`

SetNotifyOn sets NotifyOn field to given value.

### HasNotifyOn

`func (o *NotificationRule) HasNotifyOn() bool`

HasNotifyOn returns a boolean if a field has been set.

### GetMessage

`func (o *NotificationRule) GetMessage() string`

GetMessage returns the Message field if non-nil, zero value otherwise.

### GetMessageOk

`func (o *NotificationRule) GetMessageOk() (*string, bool)`

GetMessageOk returns a tuple with the Message field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMessage

`func (o *NotificationRule) SetMessage(v string)`

SetMessage sets Message field to given value.

### HasMessage

`func (o *NotificationRule) HasMessage() bool`

HasMessage returns a boolean if a field has been set.

### GetPublisher

`func (o *NotificationRule) GetPublisher() NotificationPublisher`

GetPublisher returns the Publisher field if non-nil, zero value otherwise.

### GetPublisherOk

`func (o *NotificationRule) GetPublisherOk() (*NotificationPublisher, bool)`

GetPublisherOk returns a tuple with the Publisher field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPublisher

`func (o *NotificationRule) SetPublisher(v NotificationPublisher)`

SetPublisher sets Publisher field to given value.

### HasPublisher

`func (o *NotificationRule) HasPublisher() bool`

HasPublisher returns a boolean if a field has been set.

### GetPublisherConfig

`func (o *NotificationRule) GetPublisherConfig() string`

GetPublisherConfig returns the PublisherConfig field if non-nil, zero value otherwise.

### GetPublisherConfigOk

`func (o *NotificationRule) GetPublisherConfigOk() (*string, bool)`

GetPublisherConfigOk returns a tuple with the PublisherConfig field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPublisherConfig

`func (o *NotificationRule) SetPublisherConfig(v string)`

SetPublisherConfig sets PublisherConfig field to given value.

### HasPublisherConfig

`func (o *NotificationRule) HasPublisherConfig() bool`

HasPublisherConfig returns a boolean if a field has been set.

### GetTriggerType

`func (o *NotificationRule) GetTriggerType() string`

GetTriggerType returns the TriggerType field if non-nil, zero value otherwise.

### GetTriggerTypeOk

`func (o *NotificationRule) GetTriggerTypeOk() (*string, bool)`

GetTriggerTypeOk returns a tuple with the TriggerType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTriggerType

`func (o *NotificationRule) SetTriggerType(v string)`

SetTriggerType sets TriggerType field to given value.


### GetScheduleLastTriggeredAt

`func (o *NotificationRule) GetScheduleLastTriggeredAt() int64`

GetScheduleLastTriggeredAt returns the ScheduleLastTriggeredAt field if non-nil, zero value otherwise.

### GetScheduleLastTriggeredAtOk

`func (o *NotificationRule) GetScheduleLastTriggeredAtOk() (*int64, bool)`

GetScheduleLastTriggeredAtOk returns a tuple with the ScheduleLastTriggeredAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScheduleLastTriggeredAt

`func (o *NotificationRule) SetScheduleLastTriggeredAt(v int64)`

SetScheduleLastTriggeredAt sets ScheduleLastTriggeredAt field to given value.

### HasScheduleLastTriggeredAt

`func (o *NotificationRule) HasScheduleLastTriggeredAt() bool`

HasScheduleLastTriggeredAt returns a boolean if a field has been set.

### GetScheduleNextTriggerAt

`func (o *NotificationRule) GetScheduleNextTriggerAt() int64`

GetScheduleNextTriggerAt returns the ScheduleNextTriggerAt field if non-nil, zero value otherwise.

### GetScheduleNextTriggerAtOk

`func (o *NotificationRule) GetScheduleNextTriggerAtOk() (*int64, bool)`

GetScheduleNextTriggerAtOk returns a tuple with the ScheduleNextTriggerAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScheduleNextTriggerAt

`func (o *NotificationRule) SetScheduleNextTriggerAt(v int64)`

SetScheduleNextTriggerAt sets ScheduleNextTriggerAt field to given value.

### HasScheduleNextTriggerAt

`func (o *NotificationRule) HasScheduleNextTriggerAt() bool`

HasScheduleNextTriggerAt returns a boolean if a field has been set.

### GetScheduleCron

`func (o *NotificationRule) GetScheduleCron() string`

GetScheduleCron returns the ScheduleCron field if non-nil, zero value otherwise.

### GetScheduleCronOk

`func (o *NotificationRule) GetScheduleCronOk() (*string, bool)`

GetScheduleCronOk returns a tuple with the ScheduleCron field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScheduleCron

`func (o *NotificationRule) SetScheduleCron(v string)`

SetScheduleCron sets ScheduleCron field to given value.

### HasScheduleCron

`func (o *NotificationRule) HasScheduleCron() bool`

HasScheduleCron returns a boolean if a field has been set.

### GetScheduleSkipUnchanged

`func (o *NotificationRule) GetScheduleSkipUnchanged() bool`

GetScheduleSkipUnchanged returns the ScheduleSkipUnchanged field if non-nil, zero value otherwise.

### GetScheduleSkipUnchangedOk

`func (o *NotificationRule) GetScheduleSkipUnchangedOk() (*bool, bool)`

GetScheduleSkipUnchangedOk returns a tuple with the ScheduleSkipUnchanged field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScheduleSkipUnchanged

`func (o *NotificationRule) SetScheduleSkipUnchanged(v bool)`

SetScheduleSkipUnchanged sets ScheduleSkipUnchanged field to given value.

### HasScheduleSkipUnchanged

`func (o *NotificationRule) HasScheduleSkipUnchanged() bool`

HasScheduleSkipUnchanged returns a boolean if a field has been set.

### GetUuid

`func (o *NotificationRule) GetUuid() string`

GetUuid returns the Uuid field if non-nil, zero value otherwise.

### GetUuidOk

`func (o *NotificationRule) GetUuidOk() (*string, bool)`

GetUuidOk returns a tuple with the Uuid field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUuid

`func (o *NotificationRule) SetUuid(v string)`

SetUuid sets Uuid field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


