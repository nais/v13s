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


type ConfigPropertyAPI interface {

	/*
	GetConfigProperties Returns a list of all ConfigProperties for the specified groupName

	<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiGetConfigPropertiesRequest
	*/
	GetConfigProperties(ctx context.Context) ApiGetConfigPropertiesRequest

	// GetConfigPropertiesExecute executes the request
	//  @return []ConfigProperty
	GetConfigPropertiesExecute(r ApiGetConfigPropertiesRequest) ([]ConfigProperty, *http.Response, error)

	/*
	UpdateConfigProperty Updates an array of config properties

	<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiUpdateConfigPropertyRequest
	*/
	UpdateConfigProperty(ctx context.Context) ApiUpdateConfigPropertyRequest

	// UpdateConfigPropertyExecute executes the request
	//  @return []ConfigProperty
	UpdateConfigPropertyExecute(r ApiUpdateConfigPropertyRequest) ([]ConfigProperty, *http.Response, error)

	/*
	UpdateConfigProperty1 Updates a config property

	<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiUpdateConfigProperty1Request
	*/
	UpdateConfigProperty1(ctx context.Context) ApiUpdateConfigProperty1Request

	// UpdateConfigProperty1Execute executes the request
	//  @return ConfigProperty
	UpdateConfigProperty1Execute(r ApiUpdateConfigProperty1Request) (*ConfigProperty, *http.Response, error)
}

// ConfigPropertyAPIService ConfigPropertyAPI service
type ConfigPropertyAPIService service

type ApiGetConfigPropertiesRequest struct {
	ctx context.Context
	ApiService ConfigPropertyAPI
}

func (r ApiGetConfigPropertiesRequest) Execute() ([]ConfigProperty, *http.Response, error) {
	return r.ApiService.GetConfigPropertiesExecute(r)
}

/*
GetConfigProperties Returns a list of all ConfigProperties for the specified groupName

<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiGetConfigPropertiesRequest
*/
func (a *ConfigPropertyAPIService) GetConfigProperties(ctx context.Context) ApiGetConfigPropertiesRequest {
	return ApiGetConfigPropertiesRequest{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return []ConfigProperty
func (a *ConfigPropertyAPIService) GetConfigPropertiesExecute(r ApiGetConfigPropertiesRequest) ([]ConfigProperty, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  []ConfigProperty
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ConfigPropertyAPIService.GetConfigProperties")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/configProperty"

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

type ApiUpdateConfigPropertyRequest struct {
	ctx context.Context
	ApiService ConfigPropertyAPI
	body *[]ConfigProperty
}

func (r ApiUpdateConfigPropertyRequest) Body(body []ConfigProperty) ApiUpdateConfigPropertyRequest {
	r.body = &body
	return r
}

func (r ApiUpdateConfigPropertyRequest) Execute() ([]ConfigProperty, *http.Response, error) {
	return r.ApiService.UpdateConfigPropertyExecute(r)
}

/*
UpdateConfigProperty Updates an array of config properties

<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiUpdateConfigPropertyRequest
*/
func (a *ConfigPropertyAPIService) UpdateConfigProperty(ctx context.Context) ApiUpdateConfigPropertyRequest {
	return ApiUpdateConfigPropertyRequest{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return []ConfigProperty
func (a *ConfigPropertyAPIService) UpdateConfigPropertyExecute(r ApiUpdateConfigPropertyRequest) ([]ConfigProperty, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  []ConfigProperty
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ConfigPropertyAPIService.UpdateConfigProperty")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/configProperty/aggregate"

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

type ApiUpdateConfigProperty1Request struct {
	ctx context.Context
	ApiService ConfigPropertyAPI
	body *ConfigProperty
}

func (r ApiUpdateConfigProperty1Request) Body(body ConfigProperty) ApiUpdateConfigProperty1Request {
	r.body = &body
	return r
}

func (r ApiUpdateConfigProperty1Request) Execute() (*ConfigProperty, *http.Response, error) {
	return r.ApiService.UpdateConfigProperty1Execute(r)
}

/*
UpdateConfigProperty1 Updates a config property

<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiUpdateConfigProperty1Request
*/
func (a *ConfigPropertyAPIService) UpdateConfigProperty1(ctx context.Context) ApiUpdateConfigProperty1Request {
	return ApiUpdateConfigProperty1Request{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return ConfigProperty
func (a *ConfigPropertyAPIService) UpdateConfigProperty1Execute(r ApiUpdateConfigProperty1Request) (*ConfigProperty, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *ConfigProperty
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ConfigPropertyAPIService.UpdateConfigProperty1")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/configProperty"

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
