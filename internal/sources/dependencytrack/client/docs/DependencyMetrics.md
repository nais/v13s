# DependencyMetrics

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Critical** | **int32** |  | 
**High** | **int32** |  | 
**Medium** | **int32** |  | 
**Low** | **int32** |  | 
**Unassigned** | Pointer to **int32** |  | [optional] 
**Vulnerabilities** | Pointer to **int64** |  | [optional] 
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
**FirstOccurrence** | **int64** | UNIX epoch timestamp in milliseconds | 
**LastOccurrence** | **int64** | UNIX epoch timestamp in milliseconds | 

## Methods

### NewDependencyMetrics

`func NewDependencyMetrics(critical int32, high int32, medium int32, low int32, firstOccurrence int64, lastOccurrence int64, ) *DependencyMetrics`

NewDependencyMetrics instantiates a new DependencyMetrics object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewDependencyMetricsWithDefaults

`func NewDependencyMetricsWithDefaults() *DependencyMetrics`

NewDependencyMetricsWithDefaults instantiates a new DependencyMetrics object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetCritical

`func (o *DependencyMetrics) GetCritical() int32`

GetCritical returns the Critical field if non-nil, zero value otherwise.

### GetCriticalOk

`func (o *DependencyMetrics) GetCriticalOk() (*int32, bool)`

GetCriticalOk returns a tuple with the Critical field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCritical

`func (o *DependencyMetrics) SetCritical(v int32)`

SetCritical sets Critical field to given value.


### GetHigh

`func (o *DependencyMetrics) GetHigh() int32`

GetHigh returns the High field if non-nil, zero value otherwise.

### GetHighOk

`func (o *DependencyMetrics) GetHighOk() (*int32, bool)`

GetHighOk returns a tuple with the High field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHigh

`func (o *DependencyMetrics) SetHigh(v int32)`

SetHigh sets High field to given value.


### GetMedium

`func (o *DependencyMetrics) GetMedium() int32`

GetMedium returns the Medium field if non-nil, zero value otherwise.

### GetMediumOk

`func (o *DependencyMetrics) GetMediumOk() (*int32, bool)`

GetMediumOk returns a tuple with the Medium field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMedium

`func (o *DependencyMetrics) SetMedium(v int32)`

SetMedium sets Medium field to given value.


### GetLow

`func (o *DependencyMetrics) GetLow() int32`

GetLow returns the Low field if non-nil, zero value otherwise.

### GetLowOk

`func (o *DependencyMetrics) GetLowOk() (*int32, bool)`

GetLowOk returns a tuple with the Low field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLow

`func (o *DependencyMetrics) SetLow(v int32)`

SetLow sets Low field to given value.


### GetUnassigned

`func (o *DependencyMetrics) GetUnassigned() int32`

GetUnassigned returns the Unassigned field if non-nil, zero value otherwise.

### GetUnassignedOk

`func (o *DependencyMetrics) GetUnassignedOk() (*int32, bool)`

GetUnassignedOk returns a tuple with the Unassigned field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUnassigned

`func (o *DependencyMetrics) SetUnassigned(v int32)`

SetUnassigned sets Unassigned field to given value.

### HasUnassigned

`func (o *DependencyMetrics) HasUnassigned() bool`

HasUnassigned returns a boolean if a field has been set.

### GetVulnerabilities

`func (o *DependencyMetrics) GetVulnerabilities() int64`

GetVulnerabilities returns the Vulnerabilities field if non-nil, zero value otherwise.

### GetVulnerabilitiesOk

`func (o *DependencyMetrics) GetVulnerabilitiesOk() (*int64, bool)`

GetVulnerabilitiesOk returns a tuple with the Vulnerabilities field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerabilities

`func (o *DependencyMetrics) SetVulnerabilities(v int64)`

SetVulnerabilities sets Vulnerabilities field to given value.

### HasVulnerabilities

`func (o *DependencyMetrics) HasVulnerabilities() bool`

HasVulnerabilities returns a boolean if a field has been set.

### GetSuppressed

`func (o *DependencyMetrics) GetSuppressed() int32`

GetSuppressed returns the Suppressed field if non-nil, zero value otherwise.

### GetSuppressedOk

`func (o *DependencyMetrics) GetSuppressedOk() (*int32, bool)`

GetSuppressedOk returns a tuple with the Suppressed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSuppressed

`func (o *DependencyMetrics) SetSuppressed(v int32)`

SetSuppressed sets Suppressed field to given value.

### HasSuppressed

`func (o *DependencyMetrics) HasSuppressed() bool`

HasSuppressed returns a boolean if a field has been set.

### GetFindingsTotal

`func (o *DependencyMetrics) GetFindingsTotal() int32`

GetFindingsTotal returns the FindingsTotal field if non-nil, zero value otherwise.

### GetFindingsTotalOk

`func (o *DependencyMetrics) GetFindingsTotalOk() (*int32, bool)`

GetFindingsTotalOk returns a tuple with the FindingsTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFindingsTotal

`func (o *DependencyMetrics) SetFindingsTotal(v int32)`

SetFindingsTotal sets FindingsTotal field to given value.

### HasFindingsTotal

`func (o *DependencyMetrics) HasFindingsTotal() bool`

HasFindingsTotal returns a boolean if a field has been set.

### GetFindingsAudited

`func (o *DependencyMetrics) GetFindingsAudited() int32`

GetFindingsAudited returns the FindingsAudited field if non-nil, zero value otherwise.

### GetFindingsAuditedOk

`func (o *DependencyMetrics) GetFindingsAuditedOk() (*int32, bool)`

GetFindingsAuditedOk returns a tuple with the FindingsAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFindingsAudited

`func (o *DependencyMetrics) SetFindingsAudited(v int32)`

SetFindingsAudited sets FindingsAudited field to given value.

### HasFindingsAudited

`func (o *DependencyMetrics) HasFindingsAudited() bool`

HasFindingsAudited returns a boolean if a field has been set.

### GetFindingsUnaudited

`func (o *DependencyMetrics) GetFindingsUnaudited() int32`

GetFindingsUnaudited returns the FindingsUnaudited field if non-nil, zero value otherwise.

### GetFindingsUnauditedOk

`func (o *DependencyMetrics) GetFindingsUnauditedOk() (*int32, bool)`

GetFindingsUnauditedOk returns a tuple with the FindingsUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFindingsUnaudited

`func (o *DependencyMetrics) SetFindingsUnaudited(v int32)`

SetFindingsUnaudited sets FindingsUnaudited field to given value.

### HasFindingsUnaudited

`func (o *DependencyMetrics) HasFindingsUnaudited() bool`

HasFindingsUnaudited returns a boolean if a field has been set.

### GetInheritedRiskScore

`func (o *DependencyMetrics) GetInheritedRiskScore() float64`

GetInheritedRiskScore returns the InheritedRiskScore field if non-nil, zero value otherwise.

### GetInheritedRiskScoreOk

`func (o *DependencyMetrics) GetInheritedRiskScoreOk() (*float64, bool)`

GetInheritedRiskScoreOk returns a tuple with the InheritedRiskScore field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInheritedRiskScore

`func (o *DependencyMetrics) SetInheritedRiskScore(v float64)`

SetInheritedRiskScore sets InheritedRiskScore field to given value.

### HasInheritedRiskScore

`func (o *DependencyMetrics) HasInheritedRiskScore() bool`

HasInheritedRiskScore returns a boolean if a field has been set.

### GetPolicyViolationsFail

`func (o *DependencyMetrics) GetPolicyViolationsFail() int32`

GetPolicyViolationsFail returns the PolicyViolationsFail field if non-nil, zero value otherwise.

### GetPolicyViolationsFailOk

`func (o *DependencyMetrics) GetPolicyViolationsFailOk() (*int32, bool)`

GetPolicyViolationsFailOk returns a tuple with the PolicyViolationsFail field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsFail

`func (o *DependencyMetrics) SetPolicyViolationsFail(v int32)`

SetPolicyViolationsFail sets PolicyViolationsFail field to given value.

### HasPolicyViolationsFail

`func (o *DependencyMetrics) HasPolicyViolationsFail() bool`

HasPolicyViolationsFail returns a boolean if a field has been set.

### GetPolicyViolationsWarn

`func (o *DependencyMetrics) GetPolicyViolationsWarn() int32`

GetPolicyViolationsWarn returns the PolicyViolationsWarn field if non-nil, zero value otherwise.

### GetPolicyViolationsWarnOk

`func (o *DependencyMetrics) GetPolicyViolationsWarnOk() (*int32, bool)`

GetPolicyViolationsWarnOk returns a tuple with the PolicyViolationsWarn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsWarn

`func (o *DependencyMetrics) SetPolicyViolationsWarn(v int32)`

SetPolicyViolationsWarn sets PolicyViolationsWarn field to given value.

### HasPolicyViolationsWarn

`func (o *DependencyMetrics) HasPolicyViolationsWarn() bool`

HasPolicyViolationsWarn returns a boolean if a field has been set.

### GetPolicyViolationsInfo

`func (o *DependencyMetrics) GetPolicyViolationsInfo() int32`

GetPolicyViolationsInfo returns the PolicyViolationsInfo field if non-nil, zero value otherwise.

### GetPolicyViolationsInfoOk

`func (o *DependencyMetrics) GetPolicyViolationsInfoOk() (*int32, bool)`

GetPolicyViolationsInfoOk returns a tuple with the PolicyViolationsInfo field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsInfo

`func (o *DependencyMetrics) SetPolicyViolationsInfo(v int32)`

SetPolicyViolationsInfo sets PolicyViolationsInfo field to given value.

### HasPolicyViolationsInfo

`func (o *DependencyMetrics) HasPolicyViolationsInfo() bool`

HasPolicyViolationsInfo returns a boolean if a field has been set.

### GetPolicyViolationsTotal

`func (o *DependencyMetrics) GetPolicyViolationsTotal() int32`

GetPolicyViolationsTotal returns the PolicyViolationsTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsTotalOk

`func (o *DependencyMetrics) GetPolicyViolationsTotalOk() (*int32, bool)`

GetPolicyViolationsTotalOk returns a tuple with the PolicyViolationsTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsTotal

`func (o *DependencyMetrics) SetPolicyViolationsTotal(v int32)`

SetPolicyViolationsTotal sets PolicyViolationsTotal field to given value.

### HasPolicyViolationsTotal

`func (o *DependencyMetrics) HasPolicyViolationsTotal() bool`

HasPolicyViolationsTotal returns a boolean if a field has been set.

### GetPolicyViolationsAudited

`func (o *DependencyMetrics) GetPolicyViolationsAudited() int32`

GetPolicyViolationsAudited returns the PolicyViolationsAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsAuditedOk

`func (o *DependencyMetrics) GetPolicyViolationsAuditedOk() (*int32, bool)`

GetPolicyViolationsAuditedOk returns a tuple with the PolicyViolationsAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsAudited

`func (o *DependencyMetrics) SetPolicyViolationsAudited(v int32)`

SetPolicyViolationsAudited sets PolicyViolationsAudited field to given value.

### HasPolicyViolationsAudited

`func (o *DependencyMetrics) HasPolicyViolationsAudited() bool`

HasPolicyViolationsAudited returns a boolean if a field has been set.

### GetPolicyViolationsUnaudited

`func (o *DependencyMetrics) GetPolicyViolationsUnaudited() int32`

GetPolicyViolationsUnaudited returns the PolicyViolationsUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsUnauditedOk

`func (o *DependencyMetrics) GetPolicyViolationsUnauditedOk() (*int32, bool)`

GetPolicyViolationsUnauditedOk returns a tuple with the PolicyViolationsUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsUnaudited

`func (o *DependencyMetrics) SetPolicyViolationsUnaudited(v int32)`

SetPolicyViolationsUnaudited sets PolicyViolationsUnaudited field to given value.

### HasPolicyViolationsUnaudited

`func (o *DependencyMetrics) HasPolicyViolationsUnaudited() bool`

HasPolicyViolationsUnaudited returns a boolean if a field has been set.

### GetPolicyViolationsSecurityTotal

`func (o *DependencyMetrics) GetPolicyViolationsSecurityTotal() int32`

GetPolicyViolationsSecurityTotal returns the PolicyViolationsSecurityTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsSecurityTotalOk

`func (o *DependencyMetrics) GetPolicyViolationsSecurityTotalOk() (*int32, bool)`

GetPolicyViolationsSecurityTotalOk returns a tuple with the PolicyViolationsSecurityTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsSecurityTotal

`func (o *DependencyMetrics) SetPolicyViolationsSecurityTotal(v int32)`

SetPolicyViolationsSecurityTotal sets PolicyViolationsSecurityTotal field to given value.

### HasPolicyViolationsSecurityTotal

`func (o *DependencyMetrics) HasPolicyViolationsSecurityTotal() bool`

HasPolicyViolationsSecurityTotal returns a boolean if a field has been set.

### GetPolicyViolationsSecurityAudited

`func (o *DependencyMetrics) GetPolicyViolationsSecurityAudited() int32`

GetPolicyViolationsSecurityAudited returns the PolicyViolationsSecurityAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsSecurityAuditedOk

`func (o *DependencyMetrics) GetPolicyViolationsSecurityAuditedOk() (*int32, bool)`

GetPolicyViolationsSecurityAuditedOk returns a tuple with the PolicyViolationsSecurityAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsSecurityAudited

`func (o *DependencyMetrics) SetPolicyViolationsSecurityAudited(v int32)`

SetPolicyViolationsSecurityAudited sets PolicyViolationsSecurityAudited field to given value.

### HasPolicyViolationsSecurityAudited

`func (o *DependencyMetrics) HasPolicyViolationsSecurityAudited() bool`

HasPolicyViolationsSecurityAudited returns a boolean if a field has been set.

### GetPolicyViolationsSecurityUnaudited

`func (o *DependencyMetrics) GetPolicyViolationsSecurityUnaudited() int32`

GetPolicyViolationsSecurityUnaudited returns the PolicyViolationsSecurityUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsSecurityUnauditedOk

`func (o *DependencyMetrics) GetPolicyViolationsSecurityUnauditedOk() (*int32, bool)`

GetPolicyViolationsSecurityUnauditedOk returns a tuple with the PolicyViolationsSecurityUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsSecurityUnaudited

`func (o *DependencyMetrics) SetPolicyViolationsSecurityUnaudited(v int32)`

SetPolicyViolationsSecurityUnaudited sets PolicyViolationsSecurityUnaudited field to given value.

### HasPolicyViolationsSecurityUnaudited

`func (o *DependencyMetrics) HasPolicyViolationsSecurityUnaudited() bool`

HasPolicyViolationsSecurityUnaudited returns a boolean if a field has been set.

### GetPolicyViolationsLicenseTotal

`func (o *DependencyMetrics) GetPolicyViolationsLicenseTotal() int32`

GetPolicyViolationsLicenseTotal returns the PolicyViolationsLicenseTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsLicenseTotalOk

`func (o *DependencyMetrics) GetPolicyViolationsLicenseTotalOk() (*int32, bool)`

GetPolicyViolationsLicenseTotalOk returns a tuple with the PolicyViolationsLicenseTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsLicenseTotal

`func (o *DependencyMetrics) SetPolicyViolationsLicenseTotal(v int32)`

SetPolicyViolationsLicenseTotal sets PolicyViolationsLicenseTotal field to given value.

### HasPolicyViolationsLicenseTotal

`func (o *DependencyMetrics) HasPolicyViolationsLicenseTotal() bool`

HasPolicyViolationsLicenseTotal returns a boolean if a field has been set.

### GetPolicyViolationsLicenseAudited

`func (o *DependencyMetrics) GetPolicyViolationsLicenseAudited() int32`

GetPolicyViolationsLicenseAudited returns the PolicyViolationsLicenseAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsLicenseAuditedOk

`func (o *DependencyMetrics) GetPolicyViolationsLicenseAuditedOk() (*int32, bool)`

GetPolicyViolationsLicenseAuditedOk returns a tuple with the PolicyViolationsLicenseAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsLicenseAudited

`func (o *DependencyMetrics) SetPolicyViolationsLicenseAudited(v int32)`

SetPolicyViolationsLicenseAudited sets PolicyViolationsLicenseAudited field to given value.

### HasPolicyViolationsLicenseAudited

`func (o *DependencyMetrics) HasPolicyViolationsLicenseAudited() bool`

HasPolicyViolationsLicenseAudited returns a boolean if a field has been set.

### GetPolicyViolationsLicenseUnaudited

`func (o *DependencyMetrics) GetPolicyViolationsLicenseUnaudited() int32`

GetPolicyViolationsLicenseUnaudited returns the PolicyViolationsLicenseUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsLicenseUnauditedOk

`func (o *DependencyMetrics) GetPolicyViolationsLicenseUnauditedOk() (*int32, bool)`

GetPolicyViolationsLicenseUnauditedOk returns a tuple with the PolicyViolationsLicenseUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsLicenseUnaudited

`func (o *DependencyMetrics) SetPolicyViolationsLicenseUnaudited(v int32)`

SetPolicyViolationsLicenseUnaudited sets PolicyViolationsLicenseUnaudited field to given value.

### HasPolicyViolationsLicenseUnaudited

`func (o *DependencyMetrics) HasPolicyViolationsLicenseUnaudited() bool`

HasPolicyViolationsLicenseUnaudited returns a boolean if a field has been set.

### GetPolicyViolationsOperationalTotal

`func (o *DependencyMetrics) GetPolicyViolationsOperationalTotal() int32`

GetPolicyViolationsOperationalTotal returns the PolicyViolationsOperationalTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsOperationalTotalOk

`func (o *DependencyMetrics) GetPolicyViolationsOperationalTotalOk() (*int32, bool)`

GetPolicyViolationsOperationalTotalOk returns a tuple with the PolicyViolationsOperationalTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsOperationalTotal

`func (o *DependencyMetrics) SetPolicyViolationsOperationalTotal(v int32)`

SetPolicyViolationsOperationalTotal sets PolicyViolationsOperationalTotal field to given value.

### HasPolicyViolationsOperationalTotal

`func (o *DependencyMetrics) HasPolicyViolationsOperationalTotal() bool`

HasPolicyViolationsOperationalTotal returns a boolean if a field has been set.

### GetPolicyViolationsOperationalAudited

`func (o *DependencyMetrics) GetPolicyViolationsOperationalAudited() int32`

GetPolicyViolationsOperationalAudited returns the PolicyViolationsOperationalAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsOperationalAuditedOk

`func (o *DependencyMetrics) GetPolicyViolationsOperationalAuditedOk() (*int32, bool)`

GetPolicyViolationsOperationalAuditedOk returns a tuple with the PolicyViolationsOperationalAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsOperationalAudited

`func (o *DependencyMetrics) SetPolicyViolationsOperationalAudited(v int32)`

SetPolicyViolationsOperationalAudited sets PolicyViolationsOperationalAudited field to given value.

### HasPolicyViolationsOperationalAudited

`func (o *DependencyMetrics) HasPolicyViolationsOperationalAudited() bool`

HasPolicyViolationsOperationalAudited returns a boolean if a field has been set.

### GetPolicyViolationsOperationalUnaudited

`func (o *DependencyMetrics) GetPolicyViolationsOperationalUnaudited() int32`

GetPolicyViolationsOperationalUnaudited returns the PolicyViolationsOperationalUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsOperationalUnauditedOk

`func (o *DependencyMetrics) GetPolicyViolationsOperationalUnauditedOk() (*int32, bool)`

GetPolicyViolationsOperationalUnauditedOk returns a tuple with the PolicyViolationsOperationalUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsOperationalUnaudited

`func (o *DependencyMetrics) SetPolicyViolationsOperationalUnaudited(v int32)`

SetPolicyViolationsOperationalUnaudited sets PolicyViolationsOperationalUnaudited field to given value.

### HasPolicyViolationsOperationalUnaudited

`func (o *DependencyMetrics) HasPolicyViolationsOperationalUnaudited() bool`

HasPolicyViolationsOperationalUnaudited returns a boolean if a field has been set.

### GetFirstOccurrence

`func (o *DependencyMetrics) GetFirstOccurrence() int64`

GetFirstOccurrence returns the FirstOccurrence field if non-nil, zero value otherwise.

### GetFirstOccurrenceOk

`func (o *DependencyMetrics) GetFirstOccurrenceOk() (*int64, bool)`

GetFirstOccurrenceOk returns a tuple with the FirstOccurrence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFirstOccurrence

`func (o *DependencyMetrics) SetFirstOccurrence(v int64)`

SetFirstOccurrence sets FirstOccurrence field to given value.


### GetLastOccurrence

`func (o *DependencyMetrics) GetLastOccurrence() int64`

GetLastOccurrence returns the LastOccurrence field if non-nil, zero value otherwise.

### GetLastOccurrenceOk

`func (o *DependencyMetrics) GetLastOccurrenceOk() (*int64, bool)`

GetLastOccurrenceOk returns a tuple with the LastOccurrence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastOccurrence

`func (o *DependencyMetrics) SetLastOccurrence(v int64)`

SetLastOccurrence sets LastOccurrence field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


