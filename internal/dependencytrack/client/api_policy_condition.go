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


type PolicyConditionAPI interface {

	/*
	CreatePolicyCondition Creates a new policy condition

	<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param uuid The UUID of the policy
	@return ApiCreatePolicyConditionRequest
	*/
	CreatePolicyCondition(ctx context.Context, uuid string) ApiCreatePolicyConditionRequest

	// CreatePolicyConditionExecute executes the request
	//  @return PolicyCondition
	CreatePolicyConditionExecute(r ApiCreatePolicyConditionRequest) (*PolicyCondition, *http.Response, error)

	/*
	DeletePolicyCondition Deletes a policy condition

	<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param uuid The UUID of the policy condition to delete
	@return ApiDeletePolicyConditionRequest
	*/
	DeletePolicyCondition(ctx context.Context, uuid string) ApiDeletePolicyConditionRequest

	// DeletePolicyConditionExecute executes the request
	DeletePolicyConditionExecute(r ApiDeletePolicyConditionRequest) (*http.Response, error)

	/*
	UpdatePolicyCondition Updates a policy condition

	<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiUpdatePolicyConditionRequest
	*/
	UpdatePolicyCondition(ctx context.Context) ApiUpdatePolicyConditionRequest

	// UpdatePolicyConditionExecute executes the request
	//  @return PolicyCondition
	UpdatePolicyConditionExecute(r ApiUpdatePolicyConditionRequest) (*PolicyCondition, *http.Response, error)
}

// PolicyConditionAPIService PolicyConditionAPI service
type PolicyConditionAPIService service

type ApiCreatePolicyConditionRequest struct {
	ctx context.Context
	ApiService PolicyConditionAPI
	uuid string
	body *PolicyCondition
}

func (r ApiCreatePolicyConditionRequest) Body(body PolicyCondition) ApiCreatePolicyConditionRequest {
	r.body = &body
	return r
}

func (r ApiCreatePolicyConditionRequest) Execute() (*PolicyCondition, *http.Response, error) {
	return r.ApiService.CreatePolicyConditionExecute(r)
}

/*
CreatePolicyCondition Creates a new policy condition

<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param uuid The UUID of the policy
 @return ApiCreatePolicyConditionRequest
*/
func (a *PolicyConditionAPIService) CreatePolicyCondition(ctx context.Context, uuid string) ApiCreatePolicyConditionRequest {
	return ApiCreatePolicyConditionRequest{
		ApiService: a,
		ctx: ctx,
		uuid: uuid,
	}
}

// Execute executes the request
//  @return PolicyCondition
func (a *PolicyConditionAPIService) CreatePolicyConditionExecute(r ApiCreatePolicyConditionRequest) (*PolicyCondition, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPut
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *PolicyCondition
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "PolicyConditionAPIService.CreatePolicyCondition")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/policy/{uuid}/condition"
	localVarPath = strings.Replace(localVarPath, "{"+"uuid"+"}", url.PathEscape(parameterValueToString(r.uuid, "uuid")), -1)

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

type ApiDeletePolicyConditionRequest struct {
	ctx context.Context
	ApiService PolicyConditionAPI
	uuid string
}

func (r ApiDeletePolicyConditionRequest) Execute() (*http.Response, error) {
	return r.ApiService.DeletePolicyConditionExecute(r)
}

/*
DeletePolicyCondition Deletes a policy condition

<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param uuid The UUID of the policy condition to delete
 @return ApiDeletePolicyConditionRequest
*/
func (a *PolicyConditionAPIService) DeletePolicyCondition(ctx context.Context, uuid string) ApiDeletePolicyConditionRequest {
	return ApiDeletePolicyConditionRequest{
		ApiService: a,
		ctx: ctx,
		uuid: uuid,
	}
}

// Execute executes the request
func (a *PolicyConditionAPIService) DeletePolicyConditionExecute(r ApiDeletePolicyConditionRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodDelete
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "PolicyConditionAPIService.DeletePolicyCondition")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/policy/condition/{uuid}"
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

type ApiUpdatePolicyConditionRequest struct {
	ctx context.Context
	ApiService PolicyConditionAPI
	body *PolicyCondition
}

func (r ApiUpdatePolicyConditionRequest) Body(body PolicyCondition) ApiUpdatePolicyConditionRequest {
	r.body = &body
	return r
}

func (r ApiUpdatePolicyConditionRequest) Execute() (*PolicyCondition, *http.Response, error) {
	return r.ApiService.UpdatePolicyConditionExecute(r)
}

/*
UpdatePolicyCondition Updates a policy condition

<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiUpdatePolicyConditionRequest
*/
func (a *PolicyConditionAPIService) UpdatePolicyCondition(ctx context.Context) ApiUpdatePolicyConditionRequest {
	return ApiUpdatePolicyConditionRequest{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return PolicyCondition
func (a *PolicyConditionAPIService) UpdatePolicyConditionExecute(r ApiUpdatePolicyConditionRequest) (*PolicyCondition, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *PolicyCondition
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "PolicyConditionAPIService.UpdatePolicyCondition")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/policy/condition"

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
