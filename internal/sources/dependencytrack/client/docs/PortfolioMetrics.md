# PortfolioMetrics

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Critical** | **int32** |  | 
**High** | **int32** |  | 
**Medium** | **int32** |  | 
**Low** | **int32** |  | 
**Unassigned** | Pointer to **int32** |  | [optional] 
**Vulnerabilities** | Pointer to **int32** |  | [optional] 
**Projects** | Pointer to **int32** |  | [optional] 
**VulnerableProjects** | Pointer to **int32** |  | [optional] 
**Components** | Pointer to **int32** |  | [optional] 
**VulnerableComponents** | Pointer to **int32** |  | [optional] 
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

### NewPortfolioMetrics

`func NewPortfolioMetrics(critical int32, high int32, medium int32, low int32, firstOccurrence int64, lastOccurrence int64, ) *PortfolioMetrics`

NewPortfolioMetrics instantiates a new PortfolioMetrics object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPortfolioMetricsWithDefaults

`func NewPortfolioMetricsWithDefaults() *PortfolioMetrics`

NewPortfolioMetricsWithDefaults instantiates a new PortfolioMetrics object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetCritical

`func (o *PortfolioMetrics) GetCritical() int32`

GetCritical returns the Critical field if non-nil, zero value otherwise.

### GetCriticalOk

`func (o *PortfolioMetrics) GetCriticalOk() (*int32, bool)`

GetCriticalOk returns a tuple with the Critical field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCritical

`func (o *PortfolioMetrics) SetCritical(v int32)`

SetCritical sets Critical field to given value.


### GetHigh

`func (o *PortfolioMetrics) GetHigh() int32`

GetHigh returns the High field if non-nil, zero value otherwise.

### GetHighOk

`func (o *PortfolioMetrics) GetHighOk() (*int32, bool)`

GetHighOk returns a tuple with the High field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHigh

`func (o *PortfolioMetrics) SetHigh(v int32)`

SetHigh sets High field to given value.


### GetMedium

`func (o *PortfolioMetrics) GetMedium() int32`

GetMedium returns the Medium field if non-nil, zero value otherwise.

### GetMediumOk

`func (o *PortfolioMetrics) GetMediumOk() (*int32, bool)`

GetMediumOk returns a tuple with the Medium field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMedium

`func (o *PortfolioMetrics) SetMedium(v int32)`

SetMedium sets Medium field to given value.


### GetLow

`func (o *PortfolioMetrics) GetLow() int32`

GetLow returns the Low field if non-nil, zero value otherwise.

### GetLowOk

`func (o *PortfolioMetrics) GetLowOk() (*int32, bool)`

GetLowOk returns a tuple with the Low field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLow

`func (o *PortfolioMetrics) SetLow(v int32)`

SetLow sets Low field to given value.


### GetUnassigned

`func (o *PortfolioMetrics) GetUnassigned() int32`

GetUnassigned returns the Unassigned field if non-nil, zero value otherwise.

### GetUnassignedOk

`func (o *PortfolioMetrics) GetUnassignedOk() (*int32, bool)`

GetUnassignedOk returns a tuple with the Unassigned field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUnassigned

`func (o *PortfolioMetrics) SetUnassigned(v int32)`

SetUnassigned sets Unassigned field to given value.

### HasUnassigned

`func (o *PortfolioMetrics) HasUnassigned() bool`

HasUnassigned returns a boolean if a field has been set.

### GetVulnerabilities

`func (o *PortfolioMetrics) GetVulnerabilities() int32`

GetVulnerabilities returns the Vulnerabilities field if non-nil, zero value otherwise.

### GetVulnerabilitiesOk

`func (o *PortfolioMetrics) GetVulnerabilitiesOk() (*int32, bool)`

GetVulnerabilitiesOk returns a tuple with the Vulnerabilities field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerabilities

`func (o *PortfolioMetrics) SetVulnerabilities(v int32)`

SetVulnerabilities sets Vulnerabilities field to given value.

### HasVulnerabilities

`func (o *PortfolioMetrics) HasVulnerabilities() bool`

HasVulnerabilities returns a boolean if a field has been set.

### GetProjects

`func (o *PortfolioMetrics) GetProjects() int32`

GetProjects returns the Projects field if non-nil, zero value otherwise.

### GetProjectsOk

`func (o *PortfolioMetrics) GetProjectsOk() (*int32, bool)`

GetProjectsOk returns a tuple with the Projects field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProjects

`func (o *PortfolioMetrics) SetProjects(v int32)`

SetProjects sets Projects field to given value.

### HasProjects

`func (o *PortfolioMetrics) HasProjects() bool`

HasProjects returns a boolean if a field has been set.

### GetVulnerableProjects

`func (o *PortfolioMetrics) GetVulnerableProjects() int32`

GetVulnerableProjects returns the VulnerableProjects field if non-nil, zero value otherwise.

### GetVulnerableProjectsOk

`func (o *PortfolioMetrics) GetVulnerableProjectsOk() (*int32, bool)`

GetVulnerableProjectsOk returns a tuple with the VulnerableProjects field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerableProjects

`func (o *PortfolioMetrics) SetVulnerableProjects(v int32)`

SetVulnerableProjects sets VulnerableProjects field to given value.

### HasVulnerableProjects

`func (o *PortfolioMetrics) HasVulnerableProjects() bool`

HasVulnerableProjects returns a boolean if a field has been set.

### GetComponents

`func (o *PortfolioMetrics) GetComponents() int32`

GetComponents returns the Components field if non-nil, zero value otherwise.

### GetComponentsOk

`func (o *PortfolioMetrics) GetComponentsOk() (*int32, bool)`

GetComponentsOk returns a tuple with the Components field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetComponents

`func (o *PortfolioMetrics) SetComponents(v int32)`

SetComponents sets Components field to given value.

### HasComponents

`func (o *PortfolioMetrics) HasComponents() bool`

HasComponents returns a boolean if a field has been set.

### GetVulnerableComponents

`func (o *PortfolioMetrics) GetVulnerableComponents() int32`

GetVulnerableComponents returns the VulnerableComponents field if non-nil, zero value otherwise.

### GetVulnerableComponentsOk

`func (o *PortfolioMetrics) GetVulnerableComponentsOk() (*int32, bool)`

GetVulnerableComponentsOk returns a tuple with the VulnerableComponents field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVulnerableComponents

`func (o *PortfolioMetrics) SetVulnerableComponents(v int32)`

SetVulnerableComponents sets VulnerableComponents field to given value.

### HasVulnerableComponents

`func (o *PortfolioMetrics) HasVulnerableComponents() bool`

HasVulnerableComponents returns a boolean if a field has been set.

### GetSuppressed

`func (o *PortfolioMetrics) GetSuppressed() int32`

GetSuppressed returns the Suppressed field if non-nil, zero value otherwise.

### GetSuppressedOk

`func (o *PortfolioMetrics) GetSuppressedOk() (*int32, bool)`

GetSuppressedOk returns a tuple with the Suppressed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSuppressed

`func (o *PortfolioMetrics) SetSuppressed(v int32)`

SetSuppressed sets Suppressed field to given value.

### HasSuppressed

`func (o *PortfolioMetrics) HasSuppressed() bool`

HasSuppressed returns a boolean if a field has been set.

### GetFindingsTotal

`func (o *PortfolioMetrics) GetFindingsTotal() int32`

GetFindingsTotal returns the FindingsTotal field if non-nil, zero value otherwise.

### GetFindingsTotalOk

`func (o *PortfolioMetrics) GetFindingsTotalOk() (*int32, bool)`

GetFindingsTotalOk returns a tuple with the FindingsTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFindingsTotal

`func (o *PortfolioMetrics) SetFindingsTotal(v int32)`

SetFindingsTotal sets FindingsTotal field to given value.

### HasFindingsTotal

`func (o *PortfolioMetrics) HasFindingsTotal() bool`

HasFindingsTotal returns a boolean if a field has been set.

### GetFindingsAudited

`func (o *PortfolioMetrics) GetFindingsAudited() int32`

GetFindingsAudited returns the FindingsAudited field if non-nil, zero value otherwise.

### GetFindingsAuditedOk

`func (o *PortfolioMetrics) GetFindingsAuditedOk() (*int32, bool)`

GetFindingsAuditedOk returns a tuple with the FindingsAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFindingsAudited

`func (o *PortfolioMetrics) SetFindingsAudited(v int32)`

SetFindingsAudited sets FindingsAudited field to given value.

### HasFindingsAudited

`func (o *PortfolioMetrics) HasFindingsAudited() bool`

HasFindingsAudited returns a boolean if a field has been set.

### GetFindingsUnaudited

`func (o *PortfolioMetrics) GetFindingsUnaudited() int32`

GetFindingsUnaudited returns the FindingsUnaudited field if non-nil, zero value otherwise.

### GetFindingsUnauditedOk

`func (o *PortfolioMetrics) GetFindingsUnauditedOk() (*int32, bool)`

GetFindingsUnauditedOk returns a tuple with the FindingsUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFindingsUnaudited

`func (o *PortfolioMetrics) SetFindingsUnaudited(v int32)`

SetFindingsUnaudited sets FindingsUnaudited field to given value.

### HasFindingsUnaudited

`func (o *PortfolioMetrics) HasFindingsUnaudited() bool`

HasFindingsUnaudited returns a boolean if a field has been set.

### GetInheritedRiskScore

`func (o *PortfolioMetrics) GetInheritedRiskScore() float64`

GetInheritedRiskScore returns the InheritedRiskScore field if non-nil, zero value otherwise.

### GetInheritedRiskScoreOk

`func (o *PortfolioMetrics) GetInheritedRiskScoreOk() (*float64, bool)`

GetInheritedRiskScoreOk returns a tuple with the InheritedRiskScore field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInheritedRiskScore

`func (o *PortfolioMetrics) SetInheritedRiskScore(v float64)`

SetInheritedRiskScore sets InheritedRiskScore field to given value.

### HasInheritedRiskScore

`func (o *PortfolioMetrics) HasInheritedRiskScore() bool`

HasInheritedRiskScore returns a boolean if a field has been set.

### GetPolicyViolationsFail

`func (o *PortfolioMetrics) GetPolicyViolationsFail() int32`

GetPolicyViolationsFail returns the PolicyViolationsFail field if non-nil, zero value otherwise.

### GetPolicyViolationsFailOk

`func (o *PortfolioMetrics) GetPolicyViolationsFailOk() (*int32, bool)`

GetPolicyViolationsFailOk returns a tuple with the PolicyViolationsFail field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsFail

`func (o *PortfolioMetrics) SetPolicyViolationsFail(v int32)`

SetPolicyViolationsFail sets PolicyViolationsFail field to given value.

### HasPolicyViolationsFail

`func (o *PortfolioMetrics) HasPolicyViolationsFail() bool`

HasPolicyViolationsFail returns a boolean if a field has been set.

### GetPolicyViolationsWarn

`func (o *PortfolioMetrics) GetPolicyViolationsWarn() int32`

GetPolicyViolationsWarn returns the PolicyViolationsWarn field if non-nil, zero value otherwise.

### GetPolicyViolationsWarnOk

`func (o *PortfolioMetrics) GetPolicyViolationsWarnOk() (*int32, bool)`

GetPolicyViolationsWarnOk returns a tuple with the PolicyViolationsWarn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsWarn

`func (o *PortfolioMetrics) SetPolicyViolationsWarn(v int32)`

SetPolicyViolationsWarn sets PolicyViolationsWarn field to given value.

### HasPolicyViolationsWarn

`func (o *PortfolioMetrics) HasPolicyViolationsWarn() bool`

HasPolicyViolationsWarn returns a boolean if a field has been set.

### GetPolicyViolationsInfo

`func (o *PortfolioMetrics) GetPolicyViolationsInfo() int32`

GetPolicyViolationsInfo returns the PolicyViolationsInfo field if non-nil, zero value otherwise.

### GetPolicyViolationsInfoOk

`func (o *PortfolioMetrics) GetPolicyViolationsInfoOk() (*int32, bool)`

GetPolicyViolationsInfoOk returns a tuple with the PolicyViolationsInfo field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsInfo

`func (o *PortfolioMetrics) SetPolicyViolationsInfo(v int32)`

SetPolicyViolationsInfo sets PolicyViolationsInfo field to given value.

### HasPolicyViolationsInfo

`func (o *PortfolioMetrics) HasPolicyViolationsInfo() bool`

HasPolicyViolationsInfo returns a boolean if a field has been set.

### GetPolicyViolationsTotal

`func (o *PortfolioMetrics) GetPolicyViolationsTotal() int32`

GetPolicyViolationsTotal returns the PolicyViolationsTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsTotalOk

`func (o *PortfolioMetrics) GetPolicyViolationsTotalOk() (*int32, bool)`

GetPolicyViolationsTotalOk returns a tuple with the PolicyViolationsTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsTotal

`func (o *PortfolioMetrics) SetPolicyViolationsTotal(v int32)`

SetPolicyViolationsTotal sets PolicyViolationsTotal field to given value.

### HasPolicyViolationsTotal

`func (o *PortfolioMetrics) HasPolicyViolationsTotal() bool`

HasPolicyViolationsTotal returns a boolean if a field has been set.

### GetPolicyViolationsAudited

`func (o *PortfolioMetrics) GetPolicyViolationsAudited() int32`

GetPolicyViolationsAudited returns the PolicyViolationsAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsAuditedOk

`func (o *PortfolioMetrics) GetPolicyViolationsAuditedOk() (*int32, bool)`

GetPolicyViolationsAuditedOk returns a tuple with the PolicyViolationsAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsAudited

`func (o *PortfolioMetrics) SetPolicyViolationsAudited(v int32)`

SetPolicyViolationsAudited sets PolicyViolationsAudited field to given value.

### HasPolicyViolationsAudited

`func (o *PortfolioMetrics) HasPolicyViolationsAudited() bool`

HasPolicyViolationsAudited returns a boolean if a field has been set.

### GetPolicyViolationsUnaudited

`func (o *PortfolioMetrics) GetPolicyViolationsUnaudited() int32`

GetPolicyViolationsUnaudited returns the PolicyViolationsUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsUnauditedOk

`func (o *PortfolioMetrics) GetPolicyViolationsUnauditedOk() (*int32, bool)`

GetPolicyViolationsUnauditedOk returns a tuple with the PolicyViolationsUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsUnaudited

`func (o *PortfolioMetrics) SetPolicyViolationsUnaudited(v int32)`

SetPolicyViolationsUnaudited sets PolicyViolationsUnaudited field to given value.

### HasPolicyViolationsUnaudited

`func (o *PortfolioMetrics) HasPolicyViolationsUnaudited() bool`

HasPolicyViolationsUnaudited returns a boolean if a field has been set.

### GetPolicyViolationsSecurityTotal

`func (o *PortfolioMetrics) GetPolicyViolationsSecurityTotal() int32`

GetPolicyViolationsSecurityTotal returns the PolicyViolationsSecurityTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsSecurityTotalOk

`func (o *PortfolioMetrics) GetPolicyViolationsSecurityTotalOk() (*int32, bool)`

GetPolicyViolationsSecurityTotalOk returns a tuple with the PolicyViolationsSecurityTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsSecurityTotal

`func (o *PortfolioMetrics) SetPolicyViolationsSecurityTotal(v int32)`

SetPolicyViolationsSecurityTotal sets PolicyViolationsSecurityTotal field to given value.

### HasPolicyViolationsSecurityTotal

`func (o *PortfolioMetrics) HasPolicyViolationsSecurityTotal() bool`

HasPolicyViolationsSecurityTotal returns a boolean if a field has been set.

### GetPolicyViolationsSecurityAudited

`func (o *PortfolioMetrics) GetPolicyViolationsSecurityAudited() int32`

GetPolicyViolationsSecurityAudited returns the PolicyViolationsSecurityAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsSecurityAuditedOk

`func (o *PortfolioMetrics) GetPolicyViolationsSecurityAuditedOk() (*int32, bool)`

GetPolicyViolationsSecurityAuditedOk returns a tuple with the PolicyViolationsSecurityAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsSecurityAudited

`func (o *PortfolioMetrics) SetPolicyViolationsSecurityAudited(v int32)`

SetPolicyViolationsSecurityAudited sets PolicyViolationsSecurityAudited field to given value.

### HasPolicyViolationsSecurityAudited

`func (o *PortfolioMetrics) HasPolicyViolationsSecurityAudited() bool`

HasPolicyViolationsSecurityAudited returns a boolean if a field has been set.

### GetPolicyViolationsSecurityUnaudited

`func (o *PortfolioMetrics) GetPolicyViolationsSecurityUnaudited() int32`

GetPolicyViolationsSecurityUnaudited returns the PolicyViolationsSecurityUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsSecurityUnauditedOk

`func (o *PortfolioMetrics) GetPolicyViolationsSecurityUnauditedOk() (*int32, bool)`

GetPolicyViolationsSecurityUnauditedOk returns a tuple with the PolicyViolationsSecurityUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsSecurityUnaudited

`func (o *PortfolioMetrics) SetPolicyViolationsSecurityUnaudited(v int32)`

SetPolicyViolationsSecurityUnaudited sets PolicyViolationsSecurityUnaudited field to given value.

### HasPolicyViolationsSecurityUnaudited

`func (o *PortfolioMetrics) HasPolicyViolationsSecurityUnaudited() bool`

HasPolicyViolationsSecurityUnaudited returns a boolean if a field has been set.

### GetPolicyViolationsLicenseTotal

`func (o *PortfolioMetrics) GetPolicyViolationsLicenseTotal() int32`

GetPolicyViolationsLicenseTotal returns the PolicyViolationsLicenseTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsLicenseTotalOk

`func (o *PortfolioMetrics) GetPolicyViolationsLicenseTotalOk() (*int32, bool)`

GetPolicyViolationsLicenseTotalOk returns a tuple with the PolicyViolationsLicenseTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsLicenseTotal

`func (o *PortfolioMetrics) SetPolicyViolationsLicenseTotal(v int32)`

SetPolicyViolationsLicenseTotal sets PolicyViolationsLicenseTotal field to given value.

### HasPolicyViolationsLicenseTotal

`func (o *PortfolioMetrics) HasPolicyViolationsLicenseTotal() bool`

HasPolicyViolationsLicenseTotal returns a boolean if a field has been set.

### GetPolicyViolationsLicenseAudited

`func (o *PortfolioMetrics) GetPolicyViolationsLicenseAudited() int32`

GetPolicyViolationsLicenseAudited returns the PolicyViolationsLicenseAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsLicenseAuditedOk

`func (o *PortfolioMetrics) GetPolicyViolationsLicenseAuditedOk() (*int32, bool)`

GetPolicyViolationsLicenseAuditedOk returns a tuple with the PolicyViolationsLicenseAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsLicenseAudited

`func (o *PortfolioMetrics) SetPolicyViolationsLicenseAudited(v int32)`

SetPolicyViolationsLicenseAudited sets PolicyViolationsLicenseAudited field to given value.

### HasPolicyViolationsLicenseAudited

`func (o *PortfolioMetrics) HasPolicyViolationsLicenseAudited() bool`

HasPolicyViolationsLicenseAudited returns a boolean if a field has been set.

### GetPolicyViolationsLicenseUnaudited

`func (o *PortfolioMetrics) GetPolicyViolationsLicenseUnaudited() int32`

GetPolicyViolationsLicenseUnaudited returns the PolicyViolationsLicenseUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsLicenseUnauditedOk

`func (o *PortfolioMetrics) GetPolicyViolationsLicenseUnauditedOk() (*int32, bool)`

GetPolicyViolationsLicenseUnauditedOk returns a tuple with the PolicyViolationsLicenseUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsLicenseUnaudited

`func (o *PortfolioMetrics) SetPolicyViolationsLicenseUnaudited(v int32)`

SetPolicyViolationsLicenseUnaudited sets PolicyViolationsLicenseUnaudited field to given value.

### HasPolicyViolationsLicenseUnaudited

`func (o *PortfolioMetrics) HasPolicyViolationsLicenseUnaudited() bool`

HasPolicyViolationsLicenseUnaudited returns a boolean if a field has been set.

### GetPolicyViolationsOperationalTotal

`func (o *PortfolioMetrics) GetPolicyViolationsOperationalTotal() int32`

GetPolicyViolationsOperationalTotal returns the PolicyViolationsOperationalTotal field if non-nil, zero value otherwise.

### GetPolicyViolationsOperationalTotalOk

`func (o *PortfolioMetrics) GetPolicyViolationsOperationalTotalOk() (*int32, bool)`

GetPolicyViolationsOperationalTotalOk returns a tuple with the PolicyViolationsOperationalTotal field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsOperationalTotal

`func (o *PortfolioMetrics) SetPolicyViolationsOperationalTotal(v int32)`

SetPolicyViolationsOperationalTotal sets PolicyViolationsOperationalTotal field to given value.

### HasPolicyViolationsOperationalTotal

`func (o *PortfolioMetrics) HasPolicyViolationsOperationalTotal() bool`

HasPolicyViolationsOperationalTotal returns a boolean if a field has been set.

### GetPolicyViolationsOperationalAudited

`func (o *PortfolioMetrics) GetPolicyViolationsOperationalAudited() int32`

GetPolicyViolationsOperationalAudited returns the PolicyViolationsOperationalAudited field if non-nil, zero value otherwise.

### GetPolicyViolationsOperationalAuditedOk

`func (o *PortfolioMetrics) GetPolicyViolationsOperationalAuditedOk() (*int32, bool)`

GetPolicyViolationsOperationalAuditedOk returns a tuple with the PolicyViolationsOperationalAudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsOperationalAudited

`func (o *PortfolioMetrics) SetPolicyViolationsOperationalAudited(v int32)`

SetPolicyViolationsOperationalAudited sets PolicyViolationsOperationalAudited field to given value.

### HasPolicyViolationsOperationalAudited

`func (o *PortfolioMetrics) HasPolicyViolationsOperationalAudited() bool`

HasPolicyViolationsOperationalAudited returns a boolean if a field has been set.

### GetPolicyViolationsOperationalUnaudited

`func (o *PortfolioMetrics) GetPolicyViolationsOperationalUnaudited() int32`

GetPolicyViolationsOperationalUnaudited returns the PolicyViolationsOperationalUnaudited field if non-nil, zero value otherwise.

### GetPolicyViolationsOperationalUnauditedOk

`func (o *PortfolioMetrics) GetPolicyViolationsOperationalUnauditedOk() (*int32, bool)`

GetPolicyViolationsOperationalUnauditedOk returns a tuple with the PolicyViolationsOperationalUnaudited field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPolicyViolationsOperationalUnaudited

`func (o *PortfolioMetrics) SetPolicyViolationsOperationalUnaudited(v int32)`

SetPolicyViolationsOperationalUnaudited sets PolicyViolationsOperationalUnaudited field to given value.

### HasPolicyViolationsOperationalUnaudited

`func (o *PortfolioMetrics) HasPolicyViolationsOperationalUnaudited() bool`

HasPolicyViolationsOperationalUnaudited returns a boolean if a field has been set.

### GetFirstOccurrence

`func (o *PortfolioMetrics) GetFirstOccurrence() int64`

GetFirstOccurrence returns the FirstOccurrence field if non-nil, zero value otherwise.

### GetFirstOccurrenceOk

`func (o *PortfolioMetrics) GetFirstOccurrenceOk() (*int64, bool)`

GetFirstOccurrenceOk returns a tuple with the FirstOccurrence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFirstOccurrence

`func (o *PortfolioMetrics) SetFirstOccurrence(v int64)`

SetFirstOccurrence sets FirstOccurrence field to given value.


### GetLastOccurrence

`func (o *PortfolioMetrics) GetLastOccurrence() int64`

GetLastOccurrence returns the LastOccurrence field if non-nil, zero value otherwise.

### GetLastOccurrenceOk

`func (o *PortfolioMetrics) GetLastOccurrenceOk() (*int64, bool)`

GetLastOccurrenceOk returns a tuple with the LastOccurrence field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastOccurrence

`func (o *PortfolioMetrics) SetLastOccurrence(v int64)`

SetLastOccurrence sets LastOccurrence field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


