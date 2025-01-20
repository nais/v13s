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
)


// ViolationanalysisAPIService ViolationanalysisAPI service
type ViolationanalysisAPIService service

type ApiRetrieveAnalysis1Request struct {
	ctx context.Context
	ApiService *ViolationanalysisAPIService
	component *string
	policyViolation *string
}

// The UUID of the component
func (r ApiRetrieveAnalysis1Request) Component(component string) ApiRetrieveAnalysis1Request {
	r.component = &component
	return r
}

// The UUID of the policy violation
func (r ApiRetrieveAnalysis1Request) PolicyViolation(policyViolation string) ApiRetrieveAnalysis1Request {
	r.policyViolation = &policyViolation
	return r
}

func (r ApiRetrieveAnalysis1Request) Execute() (*ViolationAnalysis, *http.Response, error) {
	return r.ApiService.RetrieveAnalysis1Execute(r)
}

/*
RetrieveAnalysis1 Retrieves a violation analysis trail

<p>Requires permission <strong>VIEW_POLICY_VIOLATION</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiRetrieveAnalysis1Request
*/
func (a *ViolationanalysisAPIService) RetrieveAnalysis1(ctx context.Context) ApiRetrieveAnalysis1Request {
	return ApiRetrieveAnalysis1Request{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return ViolationAnalysis
func (a *ViolationanalysisAPIService) RetrieveAnalysis1Execute(r ApiRetrieveAnalysis1Request) (*ViolationAnalysis, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *ViolationAnalysis
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ViolationanalysisAPIService.RetrieveAnalysis1")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/violation/analysis"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.component == nil {
		return localVarReturnValue, nil, reportError("component is required and must be specified")
	}
	if r.policyViolation == nil {
		return localVarReturnValue, nil, reportError("policyViolation is required and must be specified")
	}

	parameterAddToHeaderOrQuery(localVarQueryParams, "component", r.component, "form", "")
	parameterAddToHeaderOrQuery(localVarQueryParams, "policyViolation", r.policyViolation, "form", "")
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

type ApiUpdateAnalysis1Request struct {
	ctx context.Context
	ApiService *ViolationanalysisAPIService
	body *ViolationAnalysisRequest
}

func (r ApiUpdateAnalysis1Request) Body(body ViolationAnalysisRequest) ApiUpdateAnalysis1Request {
	r.body = &body
	return r
}

func (r ApiUpdateAnalysis1Request) Execute() (*ViolationAnalysis, *http.Response, error) {
	return r.ApiService.UpdateAnalysis1Execute(r)
}

/*
UpdateAnalysis1 Records a violation analysis decision

<p>Requires permission <strong>POLICY_VIOLATION_ANALYSIS</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiUpdateAnalysis1Request
*/
func (a *ViolationanalysisAPIService) UpdateAnalysis1(ctx context.Context) ApiUpdateAnalysis1Request {
	return ApiUpdateAnalysis1Request{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return ViolationAnalysis
func (a *ViolationanalysisAPIService) UpdateAnalysis1Execute(r ApiUpdateAnalysis1Request) (*ViolationAnalysis, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPut
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *ViolationAnalysis
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ViolationanalysisAPIService.UpdateAnalysis1")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/violation/analysis"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

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
	// body params
	localVarPostBody = r.body
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
