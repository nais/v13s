// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"
	http "net/http"

	mock "github.com/stretchr/testify/mock"
)

// MockLicenseGroupAPI is an autogenerated mock type for the LicenseGroupAPI type
type MockLicenseGroupAPI struct {
	mock.Mock
}

type MockLicenseGroupAPI_Expecter struct {
	mock *mock.Mock
}

func (_m *MockLicenseGroupAPI) EXPECT() *MockLicenseGroupAPI_Expecter {
	return &MockLicenseGroupAPI_Expecter{mock: &_m.Mock}
}

// AddLicenseToLicenseGroup provides a mock function with given fields: ctx, uuid, licenseUuid
func (_m *MockLicenseGroupAPI) AddLicenseToLicenseGroup(ctx context.Context, uuid string, licenseUuid string) ApiAddLicenseToLicenseGroupRequest {
	ret := _m.Called(ctx, uuid, licenseUuid)

	if len(ret) == 0 {
		panic("no return value specified for AddLicenseToLicenseGroup")
	}

	var r0 ApiAddLicenseToLicenseGroupRequest
	if rf, ok := ret.Get(0).(func(context.Context, string, string) ApiAddLicenseToLicenseGroupRequest); ok {
		r0 = rf(ctx, uuid, licenseUuid)
	} else {
		r0 = ret.Get(0).(ApiAddLicenseToLicenseGroupRequest)
	}

	return r0
}

// MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddLicenseToLicenseGroup'
type MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call struct {
	*mock.Call
}

// AddLicenseToLicenseGroup is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
//   - licenseUuid string
func (_e *MockLicenseGroupAPI_Expecter) AddLicenseToLicenseGroup(ctx interface{}, uuid interface{}, licenseUuid interface{}) *MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call {
	return &MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call{Call: _e.mock.On("AddLicenseToLicenseGroup", ctx, uuid, licenseUuid)}
}

func (_c *MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call) Run(run func(ctx context.Context, uuid string, licenseUuid string)) *MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call) Return(_a0 ApiAddLicenseToLicenseGroupRequest) *MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call) RunAndReturn(run func(context.Context, string, string) ApiAddLicenseToLicenseGroupRequest) *MockLicenseGroupAPI_AddLicenseToLicenseGroup_Call {
	_c.Call.Return(run)
	return _c
}

// AddLicenseToLicenseGroupExecute provides a mock function with given fields: r
func (_m *MockLicenseGroupAPI) AddLicenseToLicenseGroupExecute(r ApiAddLicenseToLicenseGroupRequest) (*LicenseGroup, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for AddLicenseToLicenseGroupExecute")
	}

	var r0 *LicenseGroup
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiAddLicenseToLicenseGroupRequest) (*LicenseGroup, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiAddLicenseToLicenseGroupRequest) *LicenseGroup); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*LicenseGroup)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiAddLicenseToLicenseGroupRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiAddLicenseToLicenseGroupRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddLicenseToLicenseGroupExecute'
type MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call struct {
	*mock.Call
}

// AddLicenseToLicenseGroupExecute is a helper method to define mock.On call
//   - r ApiAddLicenseToLicenseGroupRequest
func (_e *MockLicenseGroupAPI_Expecter) AddLicenseToLicenseGroupExecute(r interface{}) *MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call {
	return &MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call{Call: _e.mock.On("AddLicenseToLicenseGroupExecute", r)}
}

func (_c *MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call) Run(run func(r ApiAddLicenseToLicenseGroupRequest)) *MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiAddLicenseToLicenseGroupRequest))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call) Return(_a0 *LicenseGroup, _a1 *http.Response, _a2 error) *MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call) RunAndReturn(run func(ApiAddLicenseToLicenseGroupRequest) (*LicenseGroup, *http.Response, error)) *MockLicenseGroupAPI_AddLicenseToLicenseGroupExecute_Call {
	_c.Call.Return(run)
	return _c
}

// CreateLicenseGroup provides a mock function with given fields: ctx
func (_m *MockLicenseGroupAPI) CreateLicenseGroup(ctx context.Context) ApiCreateLicenseGroupRequest {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for CreateLicenseGroup")
	}

	var r0 ApiCreateLicenseGroupRequest
	if rf, ok := ret.Get(0).(func(context.Context) ApiCreateLicenseGroupRequest); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(ApiCreateLicenseGroupRequest)
	}

	return r0
}

// MockLicenseGroupAPI_CreateLicenseGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateLicenseGroup'
type MockLicenseGroupAPI_CreateLicenseGroup_Call struct {
	*mock.Call
}

// CreateLicenseGroup is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockLicenseGroupAPI_Expecter) CreateLicenseGroup(ctx interface{}) *MockLicenseGroupAPI_CreateLicenseGroup_Call {
	return &MockLicenseGroupAPI_CreateLicenseGroup_Call{Call: _e.mock.On("CreateLicenseGroup", ctx)}
}

func (_c *MockLicenseGroupAPI_CreateLicenseGroup_Call) Run(run func(ctx context.Context)) *MockLicenseGroupAPI_CreateLicenseGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_CreateLicenseGroup_Call) Return(_a0 ApiCreateLicenseGroupRequest) *MockLicenseGroupAPI_CreateLicenseGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockLicenseGroupAPI_CreateLicenseGroup_Call) RunAndReturn(run func(context.Context) ApiCreateLicenseGroupRequest) *MockLicenseGroupAPI_CreateLicenseGroup_Call {
	_c.Call.Return(run)
	return _c
}

// CreateLicenseGroupExecute provides a mock function with given fields: r
func (_m *MockLicenseGroupAPI) CreateLicenseGroupExecute(r ApiCreateLicenseGroupRequest) (*LicenseGroup, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for CreateLicenseGroupExecute")
	}

	var r0 *LicenseGroup
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiCreateLicenseGroupRequest) (*LicenseGroup, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiCreateLicenseGroupRequest) *LicenseGroup); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*LicenseGroup)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiCreateLicenseGroupRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiCreateLicenseGroupRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockLicenseGroupAPI_CreateLicenseGroupExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateLicenseGroupExecute'
type MockLicenseGroupAPI_CreateLicenseGroupExecute_Call struct {
	*mock.Call
}

// CreateLicenseGroupExecute is a helper method to define mock.On call
//   - r ApiCreateLicenseGroupRequest
func (_e *MockLicenseGroupAPI_Expecter) CreateLicenseGroupExecute(r interface{}) *MockLicenseGroupAPI_CreateLicenseGroupExecute_Call {
	return &MockLicenseGroupAPI_CreateLicenseGroupExecute_Call{Call: _e.mock.On("CreateLicenseGroupExecute", r)}
}

func (_c *MockLicenseGroupAPI_CreateLicenseGroupExecute_Call) Run(run func(r ApiCreateLicenseGroupRequest)) *MockLicenseGroupAPI_CreateLicenseGroupExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiCreateLicenseGroupRequest))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_CreateLicenseGroupExecute_Call) Return(_a0 *LicenseGroup, _a1 *http.Response, _a2 error) *MockLicenseGroupAPI_CreateLicenseGroupExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockLicenseGroupAPI_CreateLicenseGroupExecute_Call) RunAndReturn(run func(ApiCreateLicenseGroupRequest) (*LicenseGroup, *http.Response, error)) *MockLicenseGroupAPI_CreateLicenseGroupExecute_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteLicenseGroup provides a mock function with given fields: ctx, uuid
func (_m *MockLicenseGroupAPI) DeleteLicenseGroup(ctx context.Context, uuid string) ApiDeleteLicenseGroupRequest {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for DeleteLicenseGroup")
	}

	var r0 ApiDeleteLicenseGroupRequest
	if rf, ok := ret.Get(0).(func(context.Context, string) ApiDeleteLicenseGroupRequest); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(ApiDeleteLicenseGroupRequest)
	}

	return r0
}

// MockLicenseGroupAPI_DeleteLicenseGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteLicenseGroup'
type MockLicenseGroupAPI_DeleteLicenseGroup_Call struct {
	*mock.Call
}

// DeleteLicenseGroup is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
func (_e *MockLicenseGroupAPI_Expecter) DeleteLicenseGroup(ctx interface{}, uuid interface{}) *MockLicenseGroupAPI_DeleteLicenseGroup_Call {
	return &MockLicenseGroupAPI_DeleteLicenseGroup_Call{Call: _e.mock.On("DeleteLicenseGroup", ctx, uuid)}
}

func (_c *MockLicenseGroupAPI_DeleteLicenseGroup_Call) Run(run func(ctx context.Context, uuid string)) *MockLicenseGroupAPI_DeleteLicenseGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_DeleteLicenseGroup_Call) Return(_a0 ApiDeleteLicenseGroupRequest) *MockLicenseGroupAPI_DeleteLicenseGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockLicenseGroupAPI_DeleteLicenseGroup_Call) RunAndReturn(run func(context.Context, string) ApiDeleteLicenseGroupRequest) *MockLicenseGroupAPI_DeleteLicenseGroup_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteLicenseGroupExecute provides a mock function with given fields: r
func (_m *MockLicenseGroupAPI) DeleteLicenseGroupExecute(r ApiDeleteLicenseGroupRequest) (*http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for DeleteLicenseGroupExecute")
	}

	var r0 *http.Response
	var r1 error
	if rf, ok := ret.Get(0).(func(ApiDeleteLicenseGroupRequest) (*http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiDeleteLicenseGroupRequest) *http.Response); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*http.Response)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiDeleteLicenseGroupRequest) error); ok {
		r1 = rf(r)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteLicenseGroupExecute'
type MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call struct {
	*mock.Call
}

// DeleteLicenseGroupExecute is a helper method to define mock.On call
//   - r ApiDeleteLicenseGroupRequest
func (_e *MockLicenseGroupAPI_Expecter) DeleteLicenseGroupExecute(r interface{}) *MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call {
	return &MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call{Call: _e.mock.On("DeleteLicenseGroupExecute", r)}
}

func (_c *MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call) Run(run func(r ApiDeleteLicenseGroupRequest)) *MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiDeleteLicenseGroupRequest))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call) Return(_a0 *http.Response, _a1 error) *MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call) RunAndReturn(run func(ApiDeleteLicenseGroupRequest) (*http.Response, error)) *MockLicenseGroupAPI_DeleteLicenseGroupExecute_Call {
	_c.Call.Return(run)
	return _c
}

// GetLicenseGroup provides a mock function with given fields: ctx, uuid
func (_m *MockLicenseGroupAPI) GetLicenseGroup(ctx context.Context, uuid string) ApiGetLicenseGroupRequest {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for GetLicenseGroup")
	}

	var r0 ApiGetLicenseGroupRequest
	if rf, ok := ret.Get(0).(func(context.Context, string) ApiGetLicenseGroupRequest); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(ApiGetLicenseGroupRequest)
	}

	return r0
}

// MockLicenseGroupAPI_GetLicenseGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetLicenseGroup'
type MockLicenseGroupAPI_GetLicenseGroup_Call struct {
	*mock.Call
}

// GetLicenseGroup is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
func (_e *MockLicenseGroupAPI_Expecter) GetLicenseGroup(ctx interface{}, uuid interface{}) *MockLicenseGroupAPI_GetLicenseGroup_Call {
	return &MockLicenseGroupAPI_GetLicenseGroup_Call{Call: _e.mock.On("GetLicenseGroup", ctx, uuid)}
}

func (_c *MockLicenseGroupAPI_GetLicenseGroup_Call) Run(run func(ctx context.Context, uuid string)) *MockLicenseGroupAPI_GetLicenseGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_GetLicenseGroup_Call) Return(_a0 ApiGetLicenseGroupRequest) *MockLicenseGroupAPI_GetLicenseGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockLicenseGroupAPI_GetLicenseGroup_Call) RunAndReturn(run func(context.Context, string) ApiGetLicenseGroupRequest) *MockLicenseGroupAPI_GetLicenseGroup_Call {
	_c.Call.Return(run)
	return _c
}

// GetLicenseGroupExecute provides a mock function with given fields: r
func (_m *MockLicenseGroupAPI) GetLicenseGroupExecute(r ApiGetLicenseGroupRequest) (*License, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetLicenseGroupExecute")
	}

	var r0 *License
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetLicenseGroupRequest) (*License, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetLicenseGroupRequest) *License); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*License)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetLicenseGroupRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetLicenseGroupRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockLicenseGroupAPI_GetLicenseGroupExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetLicenseGroupExecute'
type MockLicenseGroupAPI_GetLicenseGroupExecute_Call struct {
	*mock.Call
}

// GetLicenseGroupExecute is a helper method to define mock.On call
//   - r ApiGetLicenseGroupRequest
func (_e *MockLicenseGroupAPI_Expecter) GetLicenseGroupExecute(r interface{}) *MockLicenseGroupAPI_GetLicenseGroupExecute_Call {
	return &MockLicenseGroupAPI_GetLicenseGroupExecute_Call{Call: _e.mock.On("GetLicenseGroupExecute", r)}
}

func (_c *MockLicenseGroupAPI_GetLicenseGroupExecute_Call) Run(run func(r ApiGetLicenseGroupRequest)) *MockLicenseGroupAPI_GetLicenseGroupExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetLicenseGroupRequest))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_GetLicenseGroupExecute_Call) Return(_a0 *License, _a1 *http.Response, _a2 error) *MockLicenseGroupAPI_GetLicenseGroupExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockLicenseGroupAPI_GetLicenseGroupExecute_Call) RunAndReturn(run func(ApiGetLicenseGroupRequest) (*License, *http.Response, error)) *MockLicenseGroupAPI_GetLicenseGroupExecute_Call {
	_c.Call.Return(run)
	return _c
}

// GetLicenseGroups provides a mock function with given fields: ctx
func (_m *MockLicenseGroupAPI) GetLicenseGroups(ctx context.Context) ApiGetLicenseGroupsRequest {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetLicenseGroups")
	}

	var r0 ApiGetLicenseGroupsRequest
	if rf, ok := ret.Get(0).(func(context.Context) ApiGetLicenseGroupsRequest); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(ApiGetLicenseGroupsRequest)
	}

	return r0
}

// MockLicenseGroupAPI_GetLicenseGroups_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetLicenseGroups'
type MockLicenseGroupAPI_GetLicenseGroups_Call struct {
	*mock.Call
}

// GetLicenseGroups is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockLicenseGroupAPI_Expecter) GetLicenseGroups(ctx interface{}) *MockLicenseGroupAPI_GetLicenseGroups_Call {
	return &MockLicenseGroupAPI_GetLicenseGroups_Call{Call: _e.mock.On("GetLicenseGroups", ctx)}
}

func (_c *MockLicenseGroupAPI_GetLicenseGroups_Call) Run(run func(ctx context.Context)) *MockLicenseGroupAPI_GetLicenseGroups_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_GetLicenseGroups_Call) Return(_a0 ApiGetLicenseGroupsRequest) *MockLicenseGroupAPI_GetLicenseGroups_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockLicenseGroupAPI_GetLicenseGroups_Call) RunAndReturn(run func(context.Context) ApiGetLicenseGroupsRequest) *MockLicenseGroupAPI_GetLicenseGroups_Call {
	_c.Call.Return(run)
	return _c
}

// GetLicenseGroupsExecute provides a mock function with given fields: r
func (_m *MockLicenseGroupAPI) GetLicenseGroupsExecute(r ApiGetLicenseGroupsRequest) ([]LicenseGroup, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetLicenseGroupsExecute")
	}

	var r0 []LicenseGroup
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetLicenseGroupsRequest) ([]LicenseGroup, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetLicenseGroupsRequest) []LicenseGroup); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]LicenseGroup)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetLicenseGroupsRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetLicenseGroupsRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockLicenseGroupAPI_GetLicenseGroupsExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetLicenseGroupsExecute'
type MockLicenseGroupAPI_GetLicenseGroupsExecute_Call struct {
	*mock.Call
}

// GetLicenseGroupsExecute is a helper method to define mock.On call
//   - r ApiGetLicenseGroupsRequest
func (_e *MockLicenseGroupAPI_Expecter) GetLicenseGroupsExecute(r interface{}) *MockLicenseGroupAPI_GetLicenseGroupsExecute_Call {
	return &MockLicenseGroupAPI_GetLicenseGroupsExecute_Call{Call: _e.mock.On("GetLicenseGroupsExecute", r)}
}

func (_c *MockLicenseGroupAPI_GetLicenseGroupsExecute_Call) Run(run func(r ApiGetLicenseGroupsRequest)) *MockLicenseGroupAPI_GetLicenseGroupsExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetLicenseGroupsRequest))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_GetLicenseGroupsExecute_Call) Return(_a0 []LicenseGroup, _a1 *http.Response, _a2 error) *MockLicenseGroupAPI_GetLicenseGroupsExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockLicenseGroupAPI_GetLicenseGroupsExecute_Call) RunAndReturn(run func(ApiGetLicenseGroupsRequest) ([]LicenseGroup, *http.Response, error)) *MockLicenseGroupAPI_GetLicenseGroupsExecute_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveLicenseFromLicenseGroup provides a mock function with given fields: ctx, uuid, licenseUuid
func (_m *MockLicenseGroupAPI) RemoveLicenseFromLicenseGroup(ctx context.Context, uuid string, licenseUuid string) ApiRemoveLicenseFromLicenseGroupRequest {
	ret := _m.Called(ctx, uuid, licenseUuid)

	if len(ret) == 0 {
		panic("no return value specified for RemoveLicenseFromLicenseGroup")
	}

	var r0 ApiRemoveLicenseFromLicenseGroupRequest
	if rf, ok := ret.Get(0).(func(context.Context, string, string) ApiRemoveLicenseFromLicenseGroupRequest); ok {
		r0 = rf(ctx, uuid, licenseUuid)
	} else {
		r0 = ret.Get(0).(ApiRemoveLicenseFromLicenseGroupRequest)
	}

	return r0
}

// MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveLicenseFromLicenseGroup'
type MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call struct {
	*mock.Call
}

// RemoveLicenseFromLicenseGroup is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
//   - licenseUuid string
func (_e *MockLicenseGroupAPI_Expecter) RemoveLicenseFromLicenseGroup(ctx interface{}, uuid interface{}, licenseUuid interface{}) *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call {
	return &MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call{Call: _e.mock.On("RemoveLicenseFromLicenseGroup", ctx, uuid, licenseUuid)}
}

func (_c *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call) Run(run func(ctx context.Context, uuid string, licenseUuid string)) *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call) Return(_a0 ApiRemoveLicenseFromLicenseGroupRequest) *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call) RunAndReturn(run func(context.Context, string, string) ApiRemoveLicenseFromLicenseGroupRequest) *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroup_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveLicenseFromLicenseGroupExecute provides a mock function with given fields: r
func (_m *MockLicenseGroupAPI) RemoveLicenseFromLicenseGroupExecute(r ApiRemoveLicenseFromLicenseGroupRequest) (*LicenseGroup, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for RemoveLicenseFromLicenseGroupExecute")
	}

	var r0 *LicenseGroup
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiRemoveLicenseFromLicenseGroupRequest) (*LicenseGroup, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiRemoveLicenseFromLicenseGroupRequest) *LicenseGroup); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*LicenseGroup)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiRemoveLicenseFromLicenseGroupRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiRemoveLicenseFromLicenseGroupRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveLicenseFromLicenseGroupExecute'
type MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call struct {
	*mock.Call
}

// RemoveLicenseFromLicenseGroupExecute is a helper method to define mock.On call
//   - r ApiRemoveLicenseFromLicenseGroupRequest
func (_e *MockLicenseGroupAPI_Expecter) RemoveLicenseFromLicenseGroupExecute(r interface{}) *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call {
	return &MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call{Call: _e.mock.On("RemoveLicenseFromLicenseGroupExecute", r)}
}

func (_c *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call) Run(run func(r ApiRemoveLicenseFromLicenseGroupRequest)) *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiRemoveLicenseFromLicenseGroupRequest))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call) Return(_a0 *LicenseGroup, _a1 *http.Response, _a2 error) *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call) RunAndReturn(run func(ApiRemoveLicenseFromLicenseGroupRequest) (*LicenseGroup, *http.Response, error)) *MockLicenseGroupAPI_RemoveLicenseFromLicenseGroupExecute_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateLicenseGroup provides a mock function with given fields: ctx
func (_m *MockLicenseGroupAPI) UpdateLicenseGroup(ctx context.Context) ApiUpdateLicenseGroupRequest {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for UpdateLicenseGroup")
	}

	var r0 ApiUpdateLicenseGroupRequest
	if rf, ok := ret.Get(0).(func(context.Context) ApiUpdateLicenseGroupRequest); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(ApiUpdateLicenseGroupRequest)
	}

	return r0
}

// MockLicenseGroupAPI_UpdateLicenseGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateLicenseGroup'
type MockLicenseGroupAPI_UpdateLicenseGroup_Call struct {
	*mock.Call
}

// UpdateLicenseGroup is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockLicenseGroupAPI_Expecter) UpdateLicenseGroup(ctx interface{}) *MockLicenseGroupAPI_UpdateLicenseGroup_Call {
	return &MockLicenseGroupAPI_UpdateLicenseGroup_Call{Call: _e.mock.On("UpdateLicenseGroup", ctx)}
}

func (_c *MockLicenseGroupAPI_UpdateLicenseGroup_Call) Run(run func(ctx context.Context)) *MockLicenseGroupAPI_UpdateLicenseGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_UpdateLicenseGroup_Call) Return(_a0 ApiUpdateLicenseGroupRequest) *MockLicenseGroupAPI_UpdateLicenseGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockLicenseGroupAPI_UpdateLicenseGroup_Call) RunAndReturn(run func(context.Context) ApiUpdateLicenseGroupRequest) *MockLicenseGroupAPI_UpdateLicenseGroup_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateLicenseGroupExecute provides a mock function with given fields: r
func (_m *MockLicenseGroupAPI) UpdateLicenseGroupExecute(r ApiUpdateLicenseGroupRequest) (*LicenseGroup, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for UpdateLicenseGroupExecute")
	}

	var r0 *LicenseGroup
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiUpdateLicenseGroupRequest) (*LicenseGroup, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiUpdateLicenseGroupRequest) *LicenseGroup); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*LicenseGroup)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiUpdateLicenseGroupRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiUpdateLicenseGroupRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateLicenseGroupExecute'
type MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call struct {
	*mock.Call
}

// UpdateLicenseGroupExecute is a helper method to define mock.On call
//   - r ApiUpdateLicenseGroupRequest
func (_e *MockLicenseGroupAPI_Expecter) UpdateLicenseGroupExecute(r interface{}) *MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call {
	return &MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call{Call: _e.mock.On("UpdateLicenseGroupExecute", r)}
}

func (_c *MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call) Run(run func(r ApiUpdateLicenseGroupRequest)) *MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiUpdateLicenseGroupRequest))
	})
	return _c
}

func (_c *MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call) Return(_a0 *LicenseGroup, _a1 *http.Response, _a2 error) *MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call) RunAndReturn(run func(ApiUpdateLicenseGroupRequest) (*LicenseGroup, *http.Response, error)) *MockLicenseGroupAPI_UpdateLicenseGroupExecute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockLicenseGroupAPI creates a new instance of MockLicenseGroupAPI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockLicenseGroupAPI(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockLicenseGroupAPI {
	mock := &MockLicenseGroupAPI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
