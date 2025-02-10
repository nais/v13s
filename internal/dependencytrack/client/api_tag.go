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


type TagAPI interface {

	/*
	GetTags Returns a list of all tags associated with a given policy

	<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param policyUuid The UUID of the policy
	@return ApiGetTagsRequest
	*/
	GetTags(ctx context.Context, policyUuid string) ApiGetTagsRequest

	// GetTagsExecute executes the request
	//  @return []Tag
	GetTagsExecute(r ApiGetTagsRequest) ([]Tag, *http.Response, error)
}

// TagAPIService TagAPI service
type TagAPIService service

type ApiGetTagsRequest struct {
	ctx context.Context
	ApiService TagAPI
	policyUuid string
}

func (r ApiGetTagsRequest) Execute() ([]Tag, *http.Response, error) {
	return r.ApiService.GetTagsExecute(r)
}

/*
GetTags Returns a list of all tags associated with a given policy

<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param policyUuid The UUID of the policy
 @return ApiGetTagsRequest
*/
func (a *TagAPIService) GetTags(ctx context.Context, policyUuid string) ApiGetTagsRequest {
	return ApiGetTagsRequest{
		ApiService: a,
		ctx: ctx,
		policyUuid: policyUuid,
	}
}

// Execute executes the request
//  @return []Tag
func (a *TagAPIService) GetTagsExecute(r ApiGetTagsRequest) ([]Tag, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  []Tag
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "TagAPIService.GetTags")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/tag/{policyUuid}"
	localVarPath = strings.Replace(localVarPath, "{"+"policyUuid"+"}", url.PathEscape(parameterValueToString(r.policyUuid, "policyUuid")), -1)

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
