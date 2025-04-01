/*
Dependency-Track API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 4.11.7
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)


type FindingAPI interface {

	/*
	AnalyzeProject Triggers Vulnerability Analysis on a specific project

	<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param uuid The UUID of the project to analyze
	@return ApiAnalyzeProjectRequest
	*/
	AnalyzeProject(ctx context.Context, uuid string) ApiAnalyzeProjectRequest

	// AnalyzeProjectExecute executes the request
	//  @return Project
	AnalyzeProjectExecute(r ApiAnalyzeProjectRequest) (*Project, *http.Response, error)

	/*
	ExportFindingsByProject Returns the findings for the specified project as FPF

	<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param uuid The UUID of the project
	@return ApiExportFindingsByProjectRequest
	*/
	ExportFindingsByProject(ctx context.Context, uuid string) ApiExportFindingsByProjectRequest

	// ExportFindingsByProjectExecute executes the request
	ExportFindingsByProjectExecute(r ApiExportFindingsByProjectRequest) (*http.Response, error)

	/*
	GetAllFindings Returns a list of all findings

	<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiGetAllFindingsRequest
	*/
	GetAllFindings(ctx context.Context) ApiGetAllFindingsRequest

	// GetAllFindingsExecute executes the request
	//  @return []Finding
	GetAllFindingsExecute(r ApiGetAllFindingsRequest) ([]Finding, *http.Response, error)

	/*
	GetAllFindings1 Returns a list of all findings grouped by vulnerability

	<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiGetAllFindings1Request
	*/
	GetAllFindings1(ctx context.Context) ApiGetAllFindings1Request

	// GetAllFindings1Execute executes the request
	//  @return []GroupedFinding
	GetAllFindings1Execute(r ApiGetAllFindings1Request) ([]GroupedFinding, *http.Response, error)

	/*
	GetFindingsByProject Returns a list of all findings for a specific project or generates SARIF file if Accept: application/sarif+json header is provided

	<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param uuid The UUID of the project
	@return ApiGetFindingsByProjectRequest
	*/
	GetFindingsByProject(ctx context.Context, uuid string) ApiGetFindingsByProjectRequest

	// GetFindingsByProjectExecute executes the request
	//  @return []Finding
	GetFindingsByProjectExecute(r ApiGetFindingsByProjectRequest) ([]Finding, *http.Response, error)
}

// FindingAPIService FindingAPI service
type FindingAPIService service

type ApiAnalyzeProjectRequest struct {
	ctx context.Context
	ApiService FindingAPI
	uuid string
}

func (r ApiAnalyzeProjectRequest) Execute() (*Project, *http.Response, error) {
	return r.ApiService.AnalyzeProjectExecute(r)
}

/*
AnalyzeProject Triggers Vulnerability Analysis on a specific project

<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param uuid The UUID of the project to analyze
 @return ApiAnalyzeProjectRequest
*/
func (a *FindingAPIService) AnalyzeProject(ctx context.Context, uuid string) ApiAnalyzeProjectRequest {
	return ApiAnalyzeProjectRequest{
		ApiService: a,
		ctx: ctx,
		uuid: uuid,
	}
}

// Execute executes the request
//  @return Project
func (a *FindingAPIService) AnalyzeProjectExecute(r ApiAnalyzeProjectRequest) (*Project, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *Project
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "FindingAPIService.AnalyzeProject")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/finding/project/{uuid}/analyze"
	localVarPath = strings.Replace(localVarPath, "{"+"uuid"+"}", url.PathEscape(parameterValueToString(r.uuid, "uuid")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.ctx != nil {
		// API Key Authentication
		if auth, ok := r.ctx.Value(ContextAPIKeys).(map[string]APIKey); ok {
			if apiKey, ok := auth["X-Api-Key"]; ok {
				var key string
				if apiKey.Prefix != "" {
					key = apiKey.Prefix + " " + apiKey.Key
				} else {
					key = apiKey.Key
				}
				localVarHeaderParams["X-Api-Key"] = key
			}
		}
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiExportFindingsByProjectRequest struct {
	ctx context.Context
	ApiService FindingAPI
	uuid string
}

func (r ApiExportFindingsByProjectRequest) Execute() (*http.Response, error) {
	return r.ApiService.ExportFindingsByProjectExecute(r)
}

/*
ExportFindingsByProject Returns the findings for the specified project as FPF

<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param uuid The UUID of the project
 @return ApiExportFindingsByProjectRequest
*/
func (a *FindingAPIService) ExportFindingsByProject(ctx context.Context, uuid string) ApiExportFindingsByProjectRequest {
	return ApiExportFindingsByProjectRequest{
		ApiService: a,
		ctx: ctx,
		uuid: uuid,
	}
}

// Execute executes the request
func (a *FindingAPIService) ExportFindingsByProjectExecute(r ApiExportFindingsByProjectRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "FindingAPIService.ExportFindingsByProject")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/finding/project/{uuid}/export"
	localVarPath = strings.Replace(localVarPath, "{"+"uuid"+"}", url.PathEscape(parameterValueToString(r.uuid, "uuid")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.ctx != nil {
		// API Key Authentication
		if auth, ok := r.ctx.Value(ContextAPIKeys).(map[string]APIKey); ok {
			if apiKey, ok := auth["X-Api-Key"]; ok {
				var key string
				if apiKey.Prefix != "" {
					key = apiKey.Prefix + " " + apiKey.Key
				} else {
					key = apiKey.Key
				}
				localVarHeaderParams["X-Api-Key"] = key
			}
		}
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}

type ApiGetAllFindingsRequest struct {
	ctx context.Context
	ApiService FindingAPI
	showInactive *bool
	showSuppressed *bool
	severity *string
	analysisStatus *string
	vendorResponse *string
	publishDateFrom *string
	publishDateTo *string
	attributedOnDateFrom *string
	attributedOnDateTo *string
	textSearchField *string
	textSearchInput *string
	cvssv2From *string
	cvssv2To *string
	cvssv3From *string
	cvssv3To *string
}

// Show inactive projects
func (r ApiGetAllFindingsRequest) ShowInactive(showInactive bool) ApiGetAllFindingsRequest {
	r.showInactive = &showInactive
	return r
}

// Show suppressed findings
func (r ApiGetAllFindingsRequest) ShowSuppressed(showSuppressed bool) ApiGetAllFindingsRequest {
	r.showSuppressed = &showSuppressed
	return r
}

// Filter by severity
func (r ApiGetAllFindingsRequest) Severity(severity string) ApiGetAllFindingsRequest {
	r.severity = &severity
	return r
}

// Filter by analysis status
func (r ApiGetAllFindingsRequest) AnalysisStatus(analysisStatus string) ApiGetAllFindingsRequest {
	r.analysisStatus = &analysisStatus
	return r
}

// Filter by vendor response
func (r ApiGetAllFindingsRequest) VendorResponse(vendorResponse string) ApiGetAllFindingsRequest {
	r.vendorResponse = &vendorResponse
	return r
}

// Filter published from this date
func (r ApiGetAllFindingsRequest) PublishDateFrom(publishDateFrom string) ApiGetAllFindingsRequest {
	r.publishDateFrom = &publishDateFrom
	return r
}

// Filter published to this date
func (r ApiGetAllFindingsRequest) PublishDateTo(publishDateTo string) ApiGetAllFindingsRequest {
	r.publishDateTo = &publishDateTo
	return r
}

// Filter attributed on from this date
func (r ApiGetAllFindingsRequest) AttributedOnDateFrom(attributedOnDateFrom string) ApiGetAllFindingsRequest {
	r.attributedOnDateFrom = &attributedOnDateFrom
	return r
}

// Filter attributed on to this date
func (r ApiGetAllFindingsRequest) AttributedOnDateTo(attributedOnDateTo string) ApiGetAllFindingsRequest {
	r.attributedOnDateTo = &attributedOnDateTo
	return r
}

// Filter the text input in these fields
func (r ApiGetAllFindingsRequest) TextSearchField(textSearchField string) ApiGetAllFindingsRequest {
	r.textSearchField = &textSearchField
	return r
}

// Filter by this text input
func (r ApiGetAllFindingsRequest) TextSearchInput(textSearchInput string) ApiGetAllFindingsRequest {
	r.textSearchInput = &textSearchInput
	return r
}

// Filter CVSSv2 from this value
func (r ApiGetAllFindingsRequest) Cvssv2From(cvssv2From string) ApiGetAllFindingsRequest {
	r.cvssv2From = &cvssv2From
	return r
}

// Filter CVSSv2 from this Value
func (r ApiGetAllFindingsRequest) Cvssv2To(cvssv2To string) ApiGetAllFindingsRequest {
	r.cvssv2To = &cvssv2To
	return r
}

// Filter CVSSv3 from this value
func (r ApiGetAllFindingsRequest) Cvssv3From(cvssv3From string) ApiGetAllFindingsRequest {
	r.cvssv3From = &cvssv3From
	return r
}

// Filter CVSSv3 from this Value
func (r ApiGetAllFindingsRequest) Cvssv3To(cvssv3To string) ApiGetAllFindingsRequest {
	r.cvssv3To = &cvssv3To
	return r
}

func (r ApiGetAllFindingsRequest) Execute() ([]Finding, *http.Response, error) {
	return r.ApiService.GetAllFindingsExecute(r)
}

/*
GetAllFindings Returns a list of all findings

<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiGetAllFindingsRequest
*/
func (a *FindingAPIService) GetAllFindings(ctx context.Context) ApiGetAllFindingsRequest {
	return ApiGetAllFindingsRequest{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return []Finding
func (a *FindingAPIService) GetAllFindingsExecute(r ApiGetAllFindingsRequest) ([]Finding, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  []Finding
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "FindingAPIService.GetAllFindings")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/finding"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.showInactive != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "showInactive", r.showInactive, "form", "")
	}
	if r.showSuppressed != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "showSuppressed", r.showSuppressed, "form", "")
	}
	if r.severity != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "severity", r.severity, "form", "")
	}
	if r.analysisStatus != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "analysisStatus", r.analysisStatus, "form", "")
	}
	if r.vendorResponse != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "vendorResponse", r.vendorResponse, "form", "")
	}
	if r.publishDateFrom != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "publishDateFrom", r.publishDateFrom, "form", "")
	}
	if r.publishDateTo != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "publishDateTo", r.publishDateTo, "form", "")
	}
	if r.attributedOnDateFrom != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "attributedOnDateFrom", r.attributedOnDateFrom, "form", "")
	}
	if r.attributedOnDateTo != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "attributedOnDateTo", r.attributedOnDateTo, "form", "")
	}
	if r.textSearchField != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "textSearchField", r.textSearchField, "form", "")
	}
	if r.textSearchInput != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "textSearchInput", r.textSearchInput, "form", "")
	}
	if r.cvssv2From != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "cvssv2From", r.cvssv2From, "form", "")
	}
	if r.cvssv2To != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "cvssv2To", r.cvssv2To, "form", "")
	}
	if r.cvssv3From != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "cvssv3From", r.cvssv3From, "form", "")
	}
	if r.cvssv3To != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "cvssv3To", r.cvssv3To, "form", "")
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.ctx != nil {
		// API Key Authentication
		if auth, ok := r.ctx.Value(ContextAPIKeys).(map[string]APIKey); ok {
			if apiKey, ok := auth["X-Api-Key"]; ok {
				var key string
				if apiKey.Prefix != "" {
					key = apiKey.Prefix + " " + apiKey.Key
				} else {
					key = apiKey.Key
				}
				localVarHeaderParams["X-Api-Key"] = key
			}
		}
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiGetAllFindings1Request struct {
	ctx context.Context
	ApiService FindingAPI
	showInactive *bool
	severity *string
	publishDateFrom *string
	publishDateTo *string
	textSearchField *string
	textSearchInput *string
	cvssv2From *string
	cvssv2To *string
	cvssv3From *string
	cvssv3To *string
	occurrencesFrom *string
	occurrencesTo *string
}

// Show inactive projects
func (r ApiGetAllFindings1Request) ShowInactive(showInactive bool) ApiGetAllFindings1Request {
	r.showInactive = &showInactive
	return r
}

// Filter by severity
func (r ApiGetAllFindings1Request) Severity(severity string) ApiGetAllFindings1Request {
	r.severity = &severity
	return r
}

// Filter published from this date
func (r ApiGetAllFindings1Request) PublishDateFrom(publishDateFrom string) ApiGetAllFindings1Request {
	r.publishDateFrom = &publishDateFrom
	return r
}

// Filter published to this date
func (r ApiGetAllFindings1Request) PublishDateTo(publishDateTo string) ApiGetAllFindings1Request {
	r.publishDateTo = &publishDateTo
	return r
}

// Filter the text input in these fields
func (r ApiGetAllFindings1Request) TextSearchField(textSearchField string) ApiGetAllFindings1Request {
	r.textSearchField = &textSearchField
	return r
}

// Filter by this text input
func (r ApiGetAllFindings1Request) TextSearchInput(textSearchInput string) ApiGetAllFindings1Request {
	r.textSearchInput = &textSearchInput
	return r
}

// Filter CVSSv2 from this value
func (r ApiGetAllFindings1Request) Cvssv2From(cvssv2From string) ApiGetAllFindings1Request {
	r.cvssv2From = &cvssv2From
	return r
}

// Filter CVSSv2 to this value
func (r ApiGetAllFindings1Request) Cvssv2To(cvssv2To string) ApiGetAllFindings1Request {
	r.cvssv2To = &cvssv2To
	return r
}

// Filter CVSSv3 from this value
func (r ApiGetAllFindings1Request) Cvssv3From(cvssv3From string) ApiGetAllFindings1Request {
	r.cvssv3From = &cvssv3From
	return r
}

// Filter CVSSv3 to this value
func (r ApiGetAllFindings1Request) Cvssv3To(cvssv3To string) ApiGetAllFindings1Request {
	r.cvssv3To = &cvssv3To
	return r
}

// Filter occurrences in projects from this value
func (r ApiGetAllFindings1Request) OccurrencesFrom(occurrencesFrom string) ApiGetAllFindings1Request {
	r.occurrencesFrom = &occurrencesFrom
	return r
}

// Filter occurrences in projects to this value
func (r ApiGetAllFindings1Request) OccurrencesTo(occurrencesTo string) ApiGetAllFindings1Request {
	r.occurrencesTo = &occurrencesTo
	return r
}

func (r ApiGetAllFindings1Request) Execute() ([]GroupedFinding, *http.Response, error) {
	return r.ApiService.GetAllFindings1Execute(r)
}

/*
GetAllFindings1 Returns a list of all findings grouped by vulnerability

<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiGetAllFindings1Request
*/
func (a *FindingAPIService) GetAllFindings1(ctx context.Context) ApiGetAllFindings1Request {
	return ApiGetAllFindings1Request{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return []GroupedFinding
func (a *FindingAPIService) GetAllFindings1Execute(r ApiGetAllFindings1Request) ([]GroupedFinding, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  []GroupedFinding
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "FindingAPIService.GetAllFindings1")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/finding/grouped"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.showInactive != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "showInactive", r.showInactive, "form", "")
	}
	if r.severity != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "severity", r.severity, "form", "")
	}
	if r.publishDateFrom != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "publishDateFrom", r.publishDateFrom, "form", "")
	}
	if r.publishDateTo != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "publishDateTo", r.publishDateTo, "form", "")
	}
	if r.textSearchField != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "textSearchField", r.textSearchField, "form", "")
	}
	if r.textSearchInput != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "textSearchInput", r.textSearchInput, "form", "")
	}
	if r.cvssv2From != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "cvssv2From", r.cvssv2From, "form", "")
	}
	if r.cvssv2To != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "cvssv2To", r.cvssv2To, "form", "")
	}
	if r.cvssv3From != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "cvssv3From", r.cvssv3From, "form", "")
	}
	if r.cvssv3To != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "cvssv3To", r.cvssv3To, "form", "")
	}
	if r.occurrencesFrom != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "occurrencesFrom", r.occurrencesFrom, "form", "")
	}
	if r.occurrencesTo != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "occurrencesTo", r.occurrencesTo, "form", "")
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.ctx != nil {
		// API Key Authentication
		if auth, ok := r.ctx.Value(ContextAPIKeys).(map[string]APIKey); ok {
			if apiKey, ok := auth["X-Api-Key"]; ok {
				var key string
				if apiKey.Prefix != "" {
					key = apiKey.Prefix + " " + apiKey.Key
				} else {
					key = apiKey.Key
				}
				localVarHeaderParams["X-Api-Key"] = key
			}
		}
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiGetFindingsByProjectRequest struct {
	ctx context.Context
	ApiService FindingAPI
	uuid string
	suppressed *bool
	source *string
	accept *string
}

// Optionally includes suppressed findings
func (r ApiGetFindingsByProjectRequest) Suppressed(suppressed bool) ApiGetFindingsByProjectRequest {
	r.suppressed = &suppressed
	return r
}

// Optionally limit findings to specific sources of vulnerability intelligence
func (r ApiGetFindingsByProjectRequest) Source(source string) ApiGetFindingsByProjectRequest {
	r.source = &source
	return r
}

func (r ApiGetFindingsByProjectRequest) Accept(accept string) ApiGetFindingsByProjectRequest {
	r.accept = &accept
	return r
}

func (r ApiGetFindingsByProjectRequest) Execute() ([]Finding, *http.Response, error) {
	return r.ApiService.GetFindingsByProjectExecute(r)
}

/*
GetFindingsByProject Returns a list of all findings for a specific project or generates SARIF file if Accept: application/sarif+json header is provided

<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param uuid The UUID of the project
 @return ApiGetFindingsByProjectRequest
*/
func (a *FindingAPIService) GetFindingsByProject(ctx context.Context, uuid string) ApiGetFindingsByProjectRequest {
	return ApiGetFindingsByProjectRequest{
		ApiService: a,
		ctx: ctx,
		uuid: uuid,
	}
}

// Execute executes the request
//  @return []Finding
func (a *FindingAPIService) GetFindingsByProjectExecute(r ApiGetFindingsByProjectRequest) ([]Finding, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  []Finding
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "FindingAPIService.GetFindingsByProject")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/finding/project/{uuid}"
	localVarPath = strings.Replace(localVarPath, "{"+"uuid"+"}", url.PathEscape(parameterValueToString(r.uuid, "uuid")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.suppressed != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "suppressed", r.suppressed, "form", "")
	}
	if r.source != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "source", r.source, "form", "")
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json", "application/sarif+json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.accept != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "accept", r.accept, "simple", "")
	}
	if r.ctx != nil {
		// API Key Authentication
		if auth, ok := r.ctx.Value(ContextAPIKeys).(map[string]APIKey); ok {
			if apiKey, ok := auth["X-Api-Key"]; ok {
				var key string
				if apiKey.Prefix != "" {
					key = apiKey.Prefix + " " + apiKey.Key
				} else {
					key = apiKey.Key
				}
				localVarHeaderParams["X-Api-Key"] = key
			}
		}
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}
