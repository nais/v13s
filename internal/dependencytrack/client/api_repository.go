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


// RepositoryAPIService RepositoryAPI service
type RepositoryAPIService service

type ApiCreateRepositoryRequest struct {
	ctx context.Context
	ApiService *RepositoryAPIService
	body *Repository
}

func (r ApiCreateRepositoryRequest) Body(body Repository) ApiCreateRepositoryRequest {
	r.body = &body
	return r
}

func (r ApiCreateRepositoryRequest) Execute() (*Repository, *http.Response, error) {
	return r.ApiService.CreateRepositoryExecute(r)
}

/*
CreateRepository Creates a new repository

<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiCreateRepositoryRequest
*/
func (a *RepositoryAPIService) CreateRepository(ctx context.Context) ApiCreateRepositoryRequest {
	return ApiCreateRepositoryRequest{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return Repository
func (a *RepositoryAPIService) CreateRepositoryExecute(r ApiCreateRepositoryRequest) (*Repository, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPut
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *Repository
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "RepositoryAPIService.CreateRepository")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/repository"

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

type ApiDeleteRepositoryRequest struct {
	ctx context.Context
	ApiService *RepositoryAPIService
	uuid string
}

func (r ApiDeleteRepositoryRequest) Execute() (*http.Response, error) {
	return r.ApiService.DeleteRepositoryExecute(r)
}

/*
DeleteRepository Deletes a repository

<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param uuid The UUID of the repository to delete
 @return ApiDeleteRepositoryRequest
*/
func (a *RepositoryAPIService) DeleteRepository(ctx context.Context, uuid string) ApiDeleteRepositoryRequest {
	return ApiDeleteRepositoryRequest{
		ApiService: a,
		ctx: ctx,
		uuid: uuid,
	}
}

// Execute executes the request
func (a *RepositoryAPIService) DeleteRepositoryExecute(r ApiDeleteRepositoryRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodDelete
		localVarPostBody     interface{}
		formFiles            []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "RepositoryAPIService.DeleteRepository")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/repository/{uuid}"
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

type ApiGetRepositoriesRequest struct {
	ctx context.Context
	ApiService *RepositoryAPIService
	pageNumber *interface{}
	pageSize *interface{}
	offset *interface{}
	limit *interface{}
	sortName *string
	sortOrder *string
}

// The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;.
func (r ApiGetRepositoriesRequest) PageNumber(pageNumber interface{}) ApiGetRepositoriesRequest {
	r.pageNumber = &pageNumber
	return r
}

// Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;.
func (r ApiGetRepositoriesRequest) PageSize(pageSize interface{}) ApiGetRepositoriesRequest {
	r.pageSize = &pageSize
	return r
}

// Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;.
func (r ApiGetRepositoriesRequest) Offset(offset interface{}) ApiGetRepositoriesRequest {
	r.offset = &offset
	return r
}

// Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;.
func (r ApiGetRepositoriesRequest) Limit(limit interface{}) ApiGetRepositoriesRequest {
	r.limit = &limit
	return r
}

// Name of the resource field to sort on.
func (r ApiGetRepositoriesRequest) SortName(sortName string) ApiGetRepositoriesRequest {
	r.sortName = &sortName
	return r
}

// Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;.
func (r ApiGetRepositoriesRequest) SortOrder(sortOrder string) ApiGetRepositoriesRequest {
	r.sortOrder = &sortOrder
	return r
}

func (r ApiGetRepositoriesRequest) Execute() ([]Repository, *http.Response, error) {
	return r.ApiService.GetRepositoriesExecute(r)
}

/*
GetRepositories Returns a list of all repositories

<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiGetRepositoriesRequest
*/
func (a *RepositoryAPIService) GetRepositories(ctx context.Context) ApiGetRepositoriesRequest {
	return ApiGetRepositoriesRequest{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return []Repository
func (a *RepositoryAPIService) GetRepositoriesExecute(r ApiGetRepositoriesRequest) ([]Repository, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  []Repository
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "RepositoryAPIService.GetRepositories")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/repository"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.pageNumber != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "pageNumber", r.pageNumber, "form", "")
	} else {
		var defaultValue interface{} = 1
		r.pageNumber = &defaultValue
	}
	if r.pageSize != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "pageSize", r.pageSize, "form", "")
	} else {
		var defaultValue interface{} = 100
		r.pageSize = &defaultValue
	}
	if r.offset != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "offset", r.offset, "form", "")
	}
	if r.limit != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit", r.limit, "form", "")
	}
	if r.sortName != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "sortName", r.sortName, "form", "")
	}
	if r.sortOrder != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "sortOrder", r.sortOrder, "form", "")
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

type ApiGetRepositoriesByTypeRequest struct {
	ctx context.Context
	ApiService *RepositoryAPIService
	type_ string
	pageNumber *interface{}
	pageSize *interface{}
	offset *interface{}
	limit *interface{}
	sortName *string
	sortOrder *string
}

// The page to return. To be used in conjunction with &lt;code&gt;pageSize&lt;/code&gt;.
func (r ApiGetRepositoriesByTypeRequest) PageNumber(pageNumber interface{}) ApiGetRepositoriesByTypeRequest {
	r.pageNumber = &pageNumber
	return r
}

// Number of elements to return per page. To be used in conjunction with &lt;code&gt;pageNumber&lt;/code&gt;.
func (r ApiGetRepositoriesByTypeRequest) PageSize(pageSize interface{}) ApiGetRepositoriesByTypeRequest {
	r.pageSize = &pageSize
	return r
}

// Offset to start returning elements from. To be used in conjunction with &lt;code&gt;limit&lt;/code&gt;.
func (r ApiGetRepositoriesByTypeRequest) Offset(offset interface{}) ApiGetRepositoriesByTypeRequest {
	r.offset = &offset
	return r
}

// Number of elements to return per page. To be used in conjunction with &lt;code&gt;offset&lt;/code&gt;.
func (r ApiGetRepositoriesByTypeRequest) Limit(limit interface{}) ApiGetRepositoriesByTypeRequest {
	r.limit = &limit
	return r
}

// Name of the resource field to sort on.
func (r ApiGetRepositoriesByTypeRequest) SortName(sortName string) ApiGetRepositoriesByTypeRequest {
	r.sortName = &sortName
	return r
}

// Ordering of items when sorting with &lt;code&gt;sortName&lt;/code&gt;.
func (r ApiGetRepositoriesByTypeRequest) SortOrder(sortOrder string) ApiGetRepositoriesByTypeRequest {
	r.sortOrder = &sortOrder
	return r
}

func (r ApiGetRepositoriesByTypeRequest) Execute() ([]Repository, *http.Response, error) {
	return r.ApiService.GetRepositoriesByTypeExecute(r)
}

/*
GetRepositoriesByType Returns repositories that support the specific type

<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param type_ The type of repositories to retrieve
 @return ApiGetRepositoriesByTypeRequest
*/
func (a *RepositoryAPIService) GetRepositoriesByType(ctx context.Context, type_ string) ApiGetRepositoriesByTypeRequest {
	return ApiGetRepositoriesByTypeRequest{
		ApiService: a,
		ctx: ctx,
		type_: type_,
	}
}

// Execute executes the request
//  @return []Repository
func (a *RepositoryAPIService) GetRepositoriesByTypeExecute(r ApiGetRepositoriesByTypeRequest) ([]Repository, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  []Repository
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "RepositoryAPIService.GetRepositoriesByType")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/repository/{type}"
	localVarPath = strings.Replace(localVarPath, "{"+"type"+"}", url.PathEscape(parameterValueToString(r.type_, "type_")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.pageNumber != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "pageNumber", r.pageNumber, "form", "")
	} else {
		var defaultValue interface{} = 1
		r.pageNumber = &defaultValue
	}
	if r.pageSize != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "pageSize", r.pageSize, "form", "")
	} else {
		var defaultValue interface{} = 100
		r.pageSize = &defaultValue
	}
	if r.offset != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "offset", r.offset, "form", "")
	}
	if r.limit != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit", r.limit, "form", "")
	}
	if r.sortName != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "sortName", r.sortName, "form", "")
	}
	if r.sortOrder != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "sortOrder", r.sortOrder, "form", "")
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

type ApiGetRepositoryMetaComponentRequest struct {
	ctx context.Context
	ApiService *RepositoryAPIService
	purl *string
}

// The Package URL for the component to query
func (r ApiGetRepositoryMetaComponentRequest) Purl(purl string) ApiGetRepositoryMetaComponentRequest {
	r.purl = &purl
	return r
}

func (r ApiGetRepositoryMetaComponentRequest) Execute() (*RepositoryMetaComponent, *http.Response, error) {
	return r.ApiService.GetRepositoryMetaComponentExecute(r)
}

/*
GetRepositoryMetaComponent Attempts to resolve the latest version of the component available in the configured repositories

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiGetRepositoryMetaComponentRequest
*/
func (a *RepositoryAPIService) GetRepositoryMetaComponent(ctx context.Context) ApiGetRepositoryMetaComponentRequest {
	return ApiGetRepositoryMetaComponentRequest{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return RepositoryMetaComponent
func (a *RepositoryAPIService) GetRepositoryMetaComponentExecute(r ApiGetRepositoryMetaComponentRequest) (*RepositoryMetaComponent, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *RepositoryMetaComponent
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "RepositoryAPIService.GetRepositoryMetaComponent")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/repository/latest"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.purl == nil {
		return localVarReturnValue, nil, reportError("purl is required and must be specified")
	}

	parameterAddToHeaderOrQuery(localVarQueryParams, "purl", r.purl, "form", "")
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

type ApiUpdateRepositoryRequest struct {
	ctx context.Context
	ApiService *RepositoryAPIService
	body *Repository
}

func (r ApiUpdateRepositoryRequest) Body(body Repository) ApiUpdateRepositoryRequest {
	r.body = &body
	return r
}

func (r ApiUpdateRepositoryRequest) Execute() (*Repository, *http.Response, error) {
	return r.ApiService.UpdateRepositoryExecute(r)
}

/*
UpdateRepository Updates a repository

<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @return ApiUpdateRepositoryRequest
*/
func (a *RepositoryAPIService) UpdateRepository(ctx context.Context) ApiUpdateRepositoryRequest {
	return ApiUpdateRepositoryRequest{
		ApiService: a,
		ctx: ctx,
	}
}

// Execute executes the request
//  @return Repository
func (a *RepositoryAPIService) UpdateRepositoryExecute(r ApiUpdateRepositoryRequest) (*Repository, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *Repository
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "RepositoryAPIService.UpdateRepository")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/repository"

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
