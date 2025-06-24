# ProjectMetrics

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Critical** | **int32** |  | 
**High** | **int32** |  | 
**Medium** | **int32** |  | 
**Low** | **int32** |  | 
**Unassigned** | Pointer to **int32** |  | [optional] 
**Vulnerabilities** | Pointer to **int64** |  | [optional] 
**VulnerableComponents** | Pointer to **int32** |  | [optional] 
**Components** | Pointer to **int32** |  | [optional] 
**Suppressed** | Pointer to **int32** |  | [optional] 
**FindingsTotal** | Pointer to **int32** |  | [optional] 
**FindingsAudited** | Pointer to **int32** |  | [optional] 
**FindingsUnaudited** | Pointer to **int32** |  | [optional] 
**InheritedRiskScore** | Pointer to **float64** |  | [optional] 
**PolicyViolationsFail** | Pointer to **int32** |  | [optional] 
**PolicyViolationsWarn** | Pointer to **int32** |  | [optional] 
**PolicyViolationsInfo** | Pointer to **int32** |  | [optional] 
**PolicyViolationsTotal** | Pointer to **int32** |  | [optional] 
**PolicyViolationsAudited** | Pointer to **int32** |  | [optional] 
**PolicyViolationsUnaudited** | Pointer to **int32** |  | [optional] 
**PolicyViolationsSecurityTotal** | Pointer to **int32** |  | [optional] 
**PolicyViolationsSecurityAudited** | Pointer to **int32** |  | [optional] 
**PolicyViolationsSecurityUnaudited** | Pointer to **int32** |  | [optional] 
**PolicyViolationsLicenseTotal** | Pointer to **int32** |  | [optional] 
**PolicyViolationsLicenseAudited** | Pointer to **int32** |  | [optional] 
**PolicyViolationsLicenseUnaudited** | Pointer to **int32** |  | [optional] 
**PolicyViolationsOperationalTotal** | Pointer to **int32** |  | [optional] 
**PolicyViolationsOperationalAudited** | Pointer to **int32** |  | [optional] 
**PolicyViolationsOperationalUnaudited** | Pointer to **int32** |  | [optional] 
**CollectionLogic** | Pointer to **string** |  | [optional] 
**CollectionLogicChanged** | Pointer to **bool** |  | [optional] 
**FirstOccurrence** | **int64** | UNIX epoch timestamp in milliseconds | 
**LastOccurrence** | **int64** | UNIX epoch timestamp in milliseconds | 

## Methods

### NewProjectMetrics

`func NewProjectMetrics(critical int32, high int32, medium int32, low int32, firstOccurrence int64, lastOccurrence int64, ) *ProjectMetrics`

NewProjectMetrics instantiates a new ProjectMetrics object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewProjectMetricsWithDefaults

`func NewProjectMetricsWithDefaults() *ProjectMetrics`

NewProjectMetricsWithDefaults instantiates a new ProjectMetrics object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetCritical

`func (o *ProjectMetrics) GetCritical() int32`

GetCritical returns the Critical field if non-nil, zero value otherwise.

### GetCriticalOk

`func (o *ProjectMetrics) GetCriticalOk() (*int32, bool)`

GetCriticalOk returns a tuple with the Critical field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCritical

`func (o *ProjectMetrics) SetCritical(v int32)`

SetCritical sets Critical field to given value.


### GetHigh

`func (o *ProjectMetrics) GetHigh() int32`

GetHigh returns the High field if non-nil, zero value otherwise.

### GetHighOk

`func (o *ProjectMetrics) GetHighOk() (*int32, bool)`

GetHighOk returns a tuple with the High field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHigh

`func (o *ProjectMetrics) SetHigh(v int32)`

SetHigh sets High field to given value.


### GetMedium

`func (o *ProjectMetrics) GetMedium() int32`

GetMedium returns the Medium field if non-nil, zero value otherwise.

### GetMediumOk

`func (o *ProjectMetrics) GetMediumOk() (*int32, bool)`

GetMediumOk returns a tuple with the Medium field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMedium

`func (o *ProjectMetrics) SetMedium(v int32)`

SetMedium sets Medium field to given value.


### GetLow

`func (o *ProjectMetrics) GetLow() int32`

GetLow returns the Low field if non-nil, zero value otherwise.

### GetLowOk

`func (o *ProjectMetrics) GetLowOk() (*int32, bool)`

GetLowOk returns a tuple with the Low field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLow

`func (o *ProjectMetrics) SetLow(v int32)`

SetLow sets Low field to given value.


### GetUnassigned

`func (o *ProjectMetrics) GetUnassigned() int32`

GetUnassigned returns the Unassigned field if non-nil, zero value otherwise.

### GetUnassignedOk

`func (o *ProjectMetrics) GetUnassignedOk() (*int32, bool)`

GetUnassignedOk returns a tuple with the Unassigned field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUnassigned

`func (o *ProjectMetrics) SetUnassigned(v int32)`

SetUnassigned sets Unassigned field to given value.

### HasUnassigned

`func (o *ProjectMetrics) HasUnassigned() bool`

HasUnassigned returns a boolean if a field has been set.

### GetVulnerabilities

`func (o *ProjectMetrics) GetVulnerabilities() int64`

GetVulnerabilities returns the Vulnerabilities field if non-nil, zero value otherwise.

### GetVulnerabilitiesOk

`func (o *ProjectMetrics) GetVulnerabilitiesOk() (*int64, bool)`

GetVulnerabilitiesOk returns a tuple with the Vulnerabilities field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerabilities

`func (o *ProjectMetrics) SetVulnerabilities(v int64)`

SetVulnerabilities sets Vulnerabilities field to given value.

### HasVulnerabilities

`func (o *ProjectMetrics) HasVulnerabilities() bool`

HasVulnerabilities returns a boolean if a field has been set.

### GetVulnerableComponents

`func (o *ProjectMetrics) GetVulnerableComponents() int32`

GetVulnerableComponents returns the VulnerableComponents field if non-nil, zero value otherwise.

### GetVulnerableComponentsOk

`func (o *ProjectMetrics) GetVulnerableComponentsOk() (*int32, bool)`

GetVulnerableComponentsOk returns a tuple with the VulnerableComponents field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerableComponents

`func (o *ProjectMetrics) SetVulnerableComponents(v int32)`

SetVulnerableComponents sets VulnerableComponents field to given value.

### HasVulnerableComponents

`func (o *ProjectMetrics) HasVulnerableComponents() bool`

HasVulnerableComponents returns a boolean if a field has been set.

### GetComponents

`func (o *ProjectMetrics) GetComponents() int32`

GetComponents returns the Components field if non-nil, zero value otherwise.

### GetComponentsOk

`func (o *ProjectMetrics) GetComponentsOk() (*int32, bool)`

GetComponentsOk returns a tuple with the Components field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComponents

`func (o *ProjectMetrics) SetComponents(v int32)`

SetComponents sets Components field to given value.

### HasComponents

`func (o *ProjectMetrics) HasComponents() bool`

HasComponents returns a boolean if a field has been set.

### GetSuppressed

`func (o *ProjectMetrics) GetSuppressed() int32`

GetSuppressed returns the Suppressed field if non-nil, zero value otherwise.

### GetSuppressedOk

`func (o *ProjectMetrics) GetSuppressedOk() (*int32, bool)`

GetSuppressedOk returns a tuple with the Suppressed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSuppressed

`func (o *ProjectMetrics) SetSuppressed(v int32)`

SetSuppressed sets Suppressed field to given value.

### HasSuppressed

`func (o *ProjectMetrics) HasSuppressed() bool`

HasSuppressed returns a boolean if a field has been set.

### GetFindingsTotal

`func (o *ProjectMetrics) GetFindingsTotal() int32`

GetFindingsTotal returns the FindingsTotal field if non-nil, zero value otherwise.

### GetFindingsTotalOk

`func (o *ProjectMetrics) GetFindingsTotalOk() (*int32, bool)`

GetFindingsTotalOk returns a tuple with the FindingsTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFindingsTotal

`func (o *ProjectMetrics) SetFindingsTotal(v int32)`

SetFindingsTotal sets FindingsTotal field to given value.

### HasFindingsTotal

`func (o *ProjectMetrics) HasFindingsTotal() bool`

HasFindingsTotal returns a boolean if a field has been set.

### GetFindingsAudited

`func (o *ProjectMetrics) GetFindingsAudited() int32`

GetFindingsAudited returns the FindingsAudited field if non-nil, zero value otherwise.

### GetFindingsAuditedOk

`func (o *ProjectMetrics) GetFindingsAuditedOk() (*int32, bool)`

GetFindingsAuditedOk returns a tuple with the FindingsAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFindingsAudited

`func (o *ProjectMetrics) SetFindingsAudited(v int32)`

SetFindingsAudited sets FindingsAudited field to given value.

### HasFindingsAudited

`func (o *ProjectMetrics) HasFindingsAudited() bool`

HasFindingsAudited returns a boolean if a field has been set.

### GetFindingsUnaudited

`func (o *ProjectMetrics) GetFindingsUnaudited() int32`

GetFindingsUnaudited returns the FindingsUnaudited field if non-nil, zero value otherwise.

### GetFindingsUnauditedOk

`func (o *ProjectMetrics) GetFindingsUnauditedOk() (*int32, bool)`

GetFindingsUnauditedOk returns a tuple with the FindingsUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFindingsUnaudited

`func (o *ProjectMetrics) SetFindingsUnaudited(v int32)`

SetFindingsUnaudited sets FindingsUnaudited field to given value.

### HasFindingsUnaudited

`func (o *ProjectMetrics) HasFindingsUnaudited() bool`

HasFindingsUnaudited returns a boolean if a field has been set.

### GetInheritedRiskScore

`func (o *ProjectMetrics) GetInheritedRiskScore() float64`

GetInheritedRiskScore returns the InheritedRiskScore field if non-nil, zero value otherwise.

### GetInheritedRiskScoreOk

`func (o *ProjectMetrics) GetInheritedRiskScoreOk() (*float64, bool)`

GetInheritedRiskScoreOk returns a tuple with the InheritedRiskScore field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInheritedRiskScore

`func (o *ProjectMetrics) SetInheritedRiskScore(v float64)`

SetInheritedRiskScore sets InheritedRiskScore field to given value.

### HasInheritedRiskScore

`func (o *ProjectMetrics) HasInheritedRiskScore() bool`

HasInheritedRiskScore returns a boolean if a field has been set.

### GetPolicyViolationsFail

`func (o *ProjectMetrics) GetPolicyViolationsFail() int32`

GetPolicyViolationsFail returns the PolicyViolationsFail field if non-nil, zero value otherwise.

### GetPolicyViolationsFailOk

`func (o *ProjectMetrics) GetPolicyViolationsFailOk() (*int32, bool)`

GetPolicyViolationsFailOk returns a tuple with the PolicyViolationsFail field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsFail

`func (o *ProjectMetrics) SetPolicyViolationsFail(v int32)`

SetPolicyViolationsFail sets PolicyViolationsFail field to given value.

### HasPolicyViolationsFail

`func (o *ProjectMetrics) HasPolicyViolationsFail() bool`

HasPolicyViolationsFail returns a boolean if a field has been set.

### GetPolicyViolationsWarn

`func (o *ProjectMetrics) GetPolicyViolationsWarn() int32`

GetPolicyViolationsWarn returns the PolicyViolationsWarn field if non-nil, zero value otherwise.

### GetPolicyViolationsWarnOk

`func (o *ProjectMetrics) GetPolicyViolationsWarnOk() (*int32, bool)`

GetPolicyViolationsWarnOk returns a tuple with the PolicyViolationsWarn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsWarn

`func (o *ProjectMetrics) SetPolicyViolationsWarn(v int32)`

SetPolicyViolationsWarn sets PolicyViolationsWarn field to given value.

### HasPolicyViolationsWarn

`func (o *ProjectMetrics) HasPolicyViolationsWarn() bool`

HasPolicyViolationsWarn returns a boolean if a field has been set.

### GetPolicyViolationsInfo

`func (o *ProjectMetrics) GetPolicyViolationsInfo() int32`

GetPolicyViolationsInfo returns the PolicyViolationsInfo field if non-nil, zero value otherwise.

### GetPolicyViolationsInfoOk

`func (o *ProjectMetrics) GetPolicyViolationsInfoOk() (*int32, bool)`

GetPolicyViolationsInfoOk returns a tuple with the PolicyViolationsInfo field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsInfo

`func (o *ProjectMetrics) SetPolicyViolationsInfo(v int32)`

SetPolicyViolationsInfo sets PolicyViolationsInfo field to given value.

### HasPolicyViolationsInfo

`func (o *ProjectMetrics) HasPolicyViolationsInfo() bool`

HasPolicyViolationsInfo returns a boolean if a field has been set.

### GetPolicyViolationsTotal

`func (o *ProjectMetrics) GetPolicyViolationsTotal() int32`

GetPolicyViolationsTotal returns the PolicyViolationsTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsTotalOk

`func (o *ProjectMetrics) GetPolicyViolationsTotalOk() (*int32, bool)`

GetPolicyViolationsTotalOk returns a tuple with the PolicyViolationsTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsTotal

`func (o *ProjectMetrics) SetPolicyViolationsTotal(v int32)`

SetPolicyViolationsTotal sets PolicyViolationsTotal field to given value.

### HasPolicyViolationsTotal

`func (o *ProjectMetrics) HasPolicyViolationsTotal() bool`

HasPolicyViolationsTotal returns a boolean if a field has been set.

### GetPolicyViolationsAudited

`func (o *ProjectMetrics) GetPolicyViolationsAudited() int32`

GetPolicyViolationsAudited returns the PolicyViolationsAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsAuditedOk

`func (o *ProjectMetrics) GetPolicyViolationsAuditedOk() (*int32, bool)`

GetPolicyViolationsAuditedOk returns a tuple with the PolicyViolationsAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsAudited

`func (o *ProjectMetrics) SetPolicyViolationsAudited(v int32)`

SetPolicyViolationsAudited sets PolicyViolationsAudited field to given value.

### HasPolicyViolationsAudited

`func (o *ProjectMetrics) HasPolicyViolationsAudited() bool`

HasPolicyViolationsAudited returns a boolean if a field has been set.

### GetPolicyViolationsUnaudited

`func (o *ProjectMetrics) GetPolicyViolationsUnaudited() int32`

GetPolicyViolationsUnaudited returns the PolicyViolationsUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsUnauditedOk

`func (o *ProjectMetrics) GetPolicyViolationsUnauditedOk() (*int32, bool)`

GetPolicyViolationsUnauditedOk returns a tuple with the PolicyViolationsUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsUnaudited

`func (o *ProjectMetrics) SetPolicyViolationsUnaudited(v int32)`

SetPolicyViolationsUnaudited sets PolicyViolationsUnaudited field to given value.

### HasPolicyViolationsUnaudited

`func (o *ProjectMetrics) HasPolicyViolationsUnaudited() bool`

HasPolicyViolationsUnaudited returns a boolean if a field has been set.

### GetPolicyViolationsSecurityTotal

`func (o *ProjectMetrics) GetPolicyViolationsSecurityTotal() int32`

GetPolicyViolationsSecurityTotal returns the PolicyViolationsSecurityTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsSecurityTotalOk

`func (o *ProjectMetrics) GetPolicyViolationsSecurityTotalOk() (*int32, bool)`

GetPolicyViolationsSecurityTotalOk returns a tuple with the PolicyViolationsSecurityTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsSecurityTotal

`func (o *ProjectMetrics) SetPolicyViolationsSecurityTotal(v int32)`

SetPolicyViolationsSecurityTotal sets PolicyViolationsSecurityTotal field to given value.

### HasPolicyViolationsSecurityTotal

`func (o *ProjectMetrics) HasPolicyViolationsSecurityTotal() bool`

HasPolicyViolationsSecurityTotal returns a boolean if a field has been set.

### GetPolicyViolationsSecurityAudited

`func (o *ProjectMetrics) GetPolicyViolationsSecurityAudited() int32`

GetPolicyViolationsSecurityAudited returns the PolicyViolationsSecurityAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsSecurityAuditedOk

`func (o *ProjectMetrics) GetPolicyViolationsSecurityAuditedOk() (*int32, bool)`

GetPolicyViolationsSecurityAuditedOk returns a tuple with the PolicyViolationsSecurityAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsSecurityAudited

`func (o *ProjectMetrics) SetPolicyViolationsSecurityAudited(v int32)`

SetPolicyViolationsSecurityAudited sets PolicyViolationsSecurityAudited field to given value.

### HasPolicyViolationsSecurityAudited

`func (o *ProjectMetrics) HasPolicyViolationsSecurityAudited() bool`

HasPolicyViolationsSecurityAudited returns a boolean if a field has been set.

### GetPolicyViolationsSecurityUnaudited

`func (o *ProjectMetrics) GetPolicyViolationsSecurityUnaudited() int32`

GetPolicyViolationsSecurityUnaudited returns the PolicyViolationsSecurityUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsSecurityUnauditedOk

`func (o *ProjectMetrics) GetPolicyViolationsSecurityUnauditedOk() (*int32, bool)`

GetPolicyViolationsSecurityUnauditedOk returns a tuple with the PolicyViolationsSecurityUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsSecurityUnaudited

`func (o *ProjectMetrics) SetPolicyViolationsSecurityUnaudited(v int32)`

SetPolicyViolationsSecurityUnaudited sets PolicyViolationsSecurityUnaudited field to given value.

### HasPolicyViolationsSecurityUnaudited

`func (o *ProjectMetrics) HasPolicyViolationsSecurityUnaudited() bool`

HasPolicyViolationsSecurityUnaudited returns a boolean if a field has been set.

### GetPolicyViolationsLicenseTotal

`func (o *ProjectMetrics) GetPolicyViolationsLicenseTotal() int32`

GetPolicyViolationsLicenseTotal returns the PolicyViolationsLicenseTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsLicenseTotalOk

`func (o *ProjectMetrics) GetPolicyViolationsLicenseTotalOk() (*int32, bool)`

GetPolicyViolationsLicenseTotalOk returns a tuple with the PolicyViolationsLicenseTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsLicenseTotal

`func (o *ProjectMetrics) SetPolicyViolationsLicenseTotal(v int32)`

SetPolicyViolationsLicenseTotal sets PolicyViolationsLicenseTotal field to given value.

### HasPolicyViolationsLicenseTotal

`func (o *ProjectMetrics) HasPolicyViolationsLicenseTotal() bool`

HasPolicyViolationsLicenseTotal returns a boolean if a field has been set.

### GetPolicyViolationsLicenseAudited

`func (o *ProjectMetrics) GetPolicyViolationsLicenseAudited() int32`

GetPolicyViolationsLicenseAudited returns the PolicyViolationsLicenseAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsLicenseAuditedOk

`func (o *ProjectMetrics) GetPolicyViolationsLicenseAuditedOk() (*int32, bool)`

GetPolicyViolationsLicenseAuditedOk returns a tuple with the PolicyViolationsLicenseAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsLicenseAudited

`func (o *ProjectMetrics) SetPolicyViolationsLicenseAudited(v int32)`

SetPolicyViolationsLicenseAudited sets PolicyViolationsLicenseAudited field to given value.

### HasPolicyViolationsLicenseAudited

`func (o *ProjectMetrics) HasPolicyViolationsLicenseAudited() bool`

HasPolicyViolationsLicenseAudited returns a boolean if a field has been set.

### GetPolicyViolationsLicenseUnaudited

`func (o *ProjectMetrics) GetPolicyViolationsLicenseUnaudited() int32`

GetPolicyViolationsLicenseUnaudited returns the PolicyViolationsLicenseUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsLicenseUnauditedOk

`func (o *ProjectMetrics) GetPolicyViolationsLicenseUnauditedOk() (*int32, bool)`

GetPolicyViolationsLicenseUnauditedOk returns a tuple with the PolicyViolationsLicenseUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsLicenseUnaudited

`func (o *ProjectMetrics) SetPolicyViolationsLicenseUnaudited(v int32)`

SetPolicyViolationsLicenseUnaudited sets PolicyViolationsLicenseUnaudited field to given value.

### HasPolicyViolationsLicenseUnaudited

`func (o *ProjectMetrics) HasPolicyViolationsLicenseUnaudited() bool`

HasPolicyViolationsLicenseUnaudited returns a boolean if a field has been set.

### GetPolicyViolationsOperationalTotal

`func (o *ProjectMetrics) GetPolicyViolationsOperationalTotal() int32`

GetPolicyViolationsOperationalTotal returns the PolicyViolationsOperationalTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsOperationalTotalOk

`func (o *ProjectMetrics) GetPolicyViolationsOperationalTotalOk() (*int32, bool)`

GetPolicyViolationsOperationalTotalOk returns a tuple with the PolicyViolationsOperationalTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsOperationalTotal

`func (o *ProjectMetrics) SetPolicyViolationsOperationalTotal(v int32)`

SetPolicyViolationsOperationalTotal sets PolicyViolationsOperationalTotal field to given value.

### HasPolicyViolationsOperationalTotal

`func (o *ProjectMetrics) HasPolicyViolationsOperationalTotal() bool`

HasPolicyViolationsOperationalTotal returns a boolean if a field has been set.

### GetPolicyViolationsOperationalAudited

`func (o *ProjectMetrics) GetPolicyViolationsOperationalAudited() int32`

GetPolicyViolationsOperationalAudited returns the PolicyViolationsOperationalAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsOperationalAuditedOk

`func (o *ProjectMetrics) GetPolicyViolationsOperationalAuditedOk() (*int32, bool)`

GetPolicyViolationsOperationalAuditedOk returns a tuple with the PolicyViolationsOperationalAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsOperationalAudited

`func (o *ProjectMetrics) SetPolicyViolationsOperationalAudited(v int32)`

SetPolicyViolationsOperationalAudited sets PolicyViolationsOperationalAudited field to given value.

### HasPolicyViolationsOperationalAudited

`func (o *ProjectMetrics) HasPolicyViolationsOperationalAudited() bool`

HasPolicyViolationsOperationalAudited returns a boolean if a field has been set.

### GetPolicyViolationsOperationalUnaudited

`func (o *ProjectMetrics) GetPolicyViolationsOperationalUnaudited() int32`

GetPolicyViolationsOperationalUnaudited returns the PolicyViolationsOperationalUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsOperationalUnauditedOk

`func (o *ProjectMetrics) GetPolicyViolationsOperationalUnauditedOk() (*int32, bool)`

GetPolicyViolationsOperationalUnauditedOk returns a tuple with the PolicyViolationsOperationalUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsOperationalUnaudited

`func (o *ProjectMetrics) SetPolicyViolationsOperationalUnaudited(v int32)`

SetPolicyViolationsOperationalUnaudited sets PolicyViolationsOperationalUnaudited field to given value.

### HasPolicyViolationsOperationalUnaudited

`func (o *ProjectMetrics) HasPolicyViolationsOperationalUnaudited() bool`

HasPolicyViolationsOperationalUnaudited returns a boolean if a field has been set.

### GetCollectionLogic

`func (o *ProjectMetrics) GetCollectionLogic() string`

GetCollectionLogic returns the CollectionLogic field if non-nil, zero value otherwise.

### GetCollectionLogicOk

`func (o *ProjectMetrics) GetCollectionLogicOk() (*string, bool)`

GetCollectionLogicOk returns a tuple with the CollectionLogic field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCollectionLogic

`func (o *ProjectMetrics) SetCollectionLogic(v string)`

SetCollectionLogic sets CollectionLogic field to given value.

### HasCollectionLogic

`func (o *ProjectMetrics) HasCollectionLogic() bool`

HasCollectionLogic returns a boolean if a field has been set.

### GetCollectionLogicChanged

`func (o *ProjectMetrics) GetCollectionLogicChanged() bool`

GetCollectionLogicChanged returns the CollectionLogicChanged field if non-nil, zero value otherwise.

### GetCollectionLogicChangedOk

`func (o *ProjectMetrics) GetCollectionLogicChangedOk() (*bool, bool)`

GetCollectionLogicChangedOk returns a tuple with the CollectionLogicChanged field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCollectionLogicChanged

`func (o *ProjectMetrics) SetCollectionLogicChanged(v bool)`

SetCollectionLogicChanged sets CollectionLogicChanged field to given value.

### HasCollectionLogicChanged

`func (o *ProjectMetrics) HasCollectionLogicChanged() bool`

HasCollectionLogicChanged returns a boolean if a field has been set.

### GetFirstOccurrence

`func (o *ProjectMetrics) GetFirstOccurrence() int64`

GetFirstOccurrence returns the FirstOccurrence field if non-nil, zero value otherwise.

### GetFirstOccurrenceOk

`func (o *ProjectMetrics) GetFirstOccurrenceOk() (*int64, bool)`

GetFirstOccurrenceOk returns a tuple with the FirstOccurrence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFirstOccurrence

`func (o *ProjectMetrics) SetFirstOccurrence(v int64)`

SetFirstOccurrence sets FirstOccurrence field to given value.


### GetLastOccurrence

`func (o *ProjectMetrics) GetLastOccurrence() int64`

GetLastOccurrence returns the LastOccurrence field if non-nil, zero value otherwise.

### GetLastOccurrenceOk

`func (o *ProjectMetrics) GetLastOccurrenceOk() (*int64, bool)`

GetLastOccurrenceOk returns a tuple with the LastOccurrence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastOccurrence

`func (o *ProjectMetrics) SetLastOccurrence(v int64)`

SetLastOccurrence sets LastOccurrence field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


