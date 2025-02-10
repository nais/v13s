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


type BadgeAPI interface {

	/*
	GetProjectPolicyViolationsBadge Returns a policy violations badge for a specific project

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param uuid The UUID of the project to retrieve a badge for
	@return ApiGetProjectPolicyViolationsBadgeRequest
	*/
	GetProjectPolicyViolationsBadge(ctx context.Context, uuid string) ApiGetProjectPolicyViolationsBadgeRequest

	// GetProjectPolicyViolationsBadgeExecute executes the request
	//  @return string
	GetProjectPolicyViolationsBadgeExecute(r ApiGetProjectPolicyViolationsBadgeRequest) (string, *http.Response, error)

	/*
	GetProjectPolicyViolationsBadge1 Returns a policy violations badge for a specific project

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param name The name of the project to query on
	@param version The version of the project to query on
	@return ApiGetProjectPolicyViolationsBadge1Request
	*/
	GetProjectPolicyViolationsBadge1(ctx context.Context, name string, version string) ApiGetProjectPolicyViolationsBadge1Request

	// GetProjectPolicyViolationsBadge1Execute executes the request
	//  @return string
	GetProjectPolicyViolationsBadge1Execute(r ApiGetProjectPolicyViolationsBadge1Request) (string, *http.Response, error)

	/*
	GetProjectVulnerabilitiesBadge Returns current metrics for a specific project

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param name The name of the project to query on
	@param version The version of the project to query on
	@return ApiGetProjectVulnerabilitiesBadgeRequest
	*/
	GetProjectVulnerabilitiesBadge(ctx context.Context, name string, version string) ApiGetProjectVulnerabilitiesBadgeRequest

	// GetProjectVulnerabilitiesBadgeExecute executes the request
	//  @return ProjectMetrics
	GetProjectVulnerabilitiesBadgeExecute(r ApiGetProjectVulnerabilitiesBadgeRequest) (*ProjectMetrics, *http.Response, error)

	/*
	GetProjectVulnerabilitiesBadge1 Returns current metrics for a specific project

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param uuid The UUID of the project to retrieve metrics for
	@return ApiGetProjectVulnerabilitiesBadge1Request
	*/
	GetProjectVulnerabilitiesBadge1(ctx context.Context, uuid string) ApiGetProjectVulnerabilitiesBadge1Request

	// GetProjectVulnerabilitiesBadge1Execute executes the request
	//  @return ProjectMetrics
	GetProjectVulnerabilitiesBadge1Execute(r ApiGetProjectVulnerabilitiesBadge1Request) (*ProjectMetrics, *http.Response, error)
}

// BadgeAPIService BadgeAPI service
type BadgeAPIService service

type ApiGetProjectPolicyViolationsBadgeRequest struct {
	ctx context.Context
	ApiService BadgeAPI
	uuid string
}

func (r ApiGetProjectPolicyViolationsBadgeRequest) Execute() (string, *http.Response, error) {
	return r.ApiService.GetProjectPolicyViolationsBadgeExecute(r)
}

/*
GetProjectPolicyViolationsBadge Returns a policy violations badge for a specific project

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param uuid The UUID of the project to retrieve a badge for
 @return ApiGetProjectPolicyViolationsBadgeRequest
*/
func (a *BadgeAPIService) GetProjectPolicyViolationsBadge(ctx context.Context, uuid string) ApiGetProjectPolicyViolationsBadgeRequest {
	return ApiGetProjectPolicyViolationsBadgeRequest{
		ApiService: a,
		ctx: ctx,
		uuid: uuid,
	}
}

// Execute executes the request
//  @return string
func (a *BadgeAPIService) GetProjectPolicyViolationsBadgeExecute(r ApiGetProjectPolicyViolationsBadgeRequest) (string, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  string
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "BadgeAPIService.GetProjectPolicyViolationsBadge")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/badge/violations/project/{uuid}"
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
	localVarHTTPHeaderAccepts := []string{"image/svg+xml"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
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

type ApiGetProjectPolicyViolationsBadge1Request struct {
	ctx context.Context
	ApiService BadgeAPI
	name string
	version string
}

func (r ApiGetProjectPolicyViolationsBadge1Request) Execute() (string, *http.Response, error) {
	return r.ApiService.GetProjectPolicyViolationsBadge1Execute(r)
}

/*
GetProjectPolicyViolationsBadge1 Returns a policy violations badge for a specific project

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param name The name of the project to query on
 @param version The version of the project to query on
 @return ApiGetProjectPolicyViolationsBadge1Request
*/
func (a *BadgeAPIService) GetProjectPolicyViolationsBadge1(ctx context.Context, name string, version string) ApiGetProjectPolicyViolationsBadge1Request {
	return ApiGetProjectPolicyViolationsBadge1Request{
		ApiService: a,
		ctx: ctx,
		name: name,
		version: version,
	}
}

// Execute executes the request
//  @return string
func (a *BadgeAPIService) GetProjectPolicyViolationsBadge1Execute(r ApiGetProjectPolicyViolationsBadge1Request) (string, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  string
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "BadgeAPIService.GetProjectPolicyViolationsBadge1")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/badge/violations/project/{name}/{version}"
	localVarPath = strings.Replace(localVarPath, "{"+"name"+"}", url.PathEscape(parameterValueToString(r.name, "name")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"version"+"}", url.PathEscape(parameterValueToString(r.version, "version")), -1)

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
	localVarHTTPHeaderAccepts := []string{"image/svg+xml"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
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

type ApiGetProjectVulnerabilitiesBadgeRequest struct {
	ctx context.Context
	ApiService BadgeAPI
	name string
	version string
}

func (r ApiGetProjectVulnerabilitiesBadgeRequest) Execute() (*ProjectMetrics, *http.Response, error) {
	return r.ApiService.GetProjectVulnerabilitiesBadgeExecute(r)
}

/*
GetProjectVulnerabilitiesBadge Returns current metrics for a specific project

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param name The name of the project to query on
 @param version The version of the project to query on
 @return ApiGetProjectVulnerabilitiesBadgeRequest
*/
func (a *BadgeAPIService) GetProjectVulnerabilitiesBadge(ctx context.Context, name string, version string) ApiGetProjectVulnerabilitiesBadgeRequest {
	return ApiGetProjectVulnerabilitiesBadgeRequest{
		ApiService: a,
		ctx: ctx,
		name: name,
		version: version,
	}
}

// Execute executes the request
//  @return ProjectMetrics
func (a *BadgeAPIService) GetProjectVulnerabilitiesBadgeExecute(r ApiGetProjectVulnerabilitiesBadgeRequest) (*ProjectMetrics, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *ProjectMetrics
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "BadgeAPIService.GetProjectVulnerabilitiesBadge")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/badge/vulns/project/{name}/{version}"
	localVarPath = strings.Replace(localVarPath, "{"+"name"+"}", url.PathEscape(parameterValueToString(r.name, "name")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"version"+"}", url.PathEscape(parameterValueToString(r.version, "version")), -1)

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
	localVarHTTPHeaderAccepts := []string{"image/svg+xml"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
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

type ApiGetProjectVulnerabilitiesBadge1Request struct {
	ctx context.Context
	ApiService BadgeAPI
	uuid string
}

func (r ApiGetProjectVulnerabilitiesBadge1Request) Execute() (*ProjectMetrics, *http.Response, error) {
	return r.ApiService.GetProjectVulnerabilitiesBadge1Execute(r)
}

/*
GetProjectVulnerabilitiesBadge1 Returns current metrics for a specific project

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param uuid The UUID of the project to retrieve metrics for
 @return ApiGetProjectVulnerabilitiesBadge1Request
*/
func (a *BadgeAPIService) GetProjectVulnerabilitiesBadge1(ctx context.Context, uuid string) ApiGetProjectVulnerabilitiesBadge1Request {
	return ApiGetProjectVulnerabilitiesBadge1Request{
		ApiService: a,
		ctx: ctx,
		uuid: uuid,
	}
}

// Execute executes the request
//  @return ProjectMetrics
func (a *BadgeAPIService) GetProjectVulnerabilitiesBadge1Execute(r ApiGetProjectVulnerabilitiesBadge1Request) (*ProjectMetrics, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *ProjectMetrics
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "BadgeAPIService.GetProjectVulnerabilitiesBadge1")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/badge/vulns/project/{uuid}"
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
	localVarHTTPHeaderAccepts := []string{"image/svg+xml"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
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
