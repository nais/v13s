// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"
	http "net/http"

	mock "github.com/stretchr/testify/mock"
)

// MockViolationAPI is an autogenerated mock type for the ViolationAPI type
type MockViolationAPI struct {
	mock.Mock
}

type MockViolationAPI_Expecter struct {
	mock *mock.Mock
}

func (_m *MockViolationAPI) EXPECT() *MockViolationAPI_Expecter {
	return &MockViolationAPI_Expecter{mock: &_m.Mock}
}

// GetViolations provides a mock function with given fields: ctx
func (_m *MockViolationAPI) GetViolations(ctx context.Context) ApiGetViolationsRequest {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetViolations")
	}

	var r0 ApiGetViolationsRequest
	if rf, ok := ret.Get(0).(func(context.Context) ApiGetViolationsRequest); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(ApiGetViolationsRequest)
	}

	return r0
}

// MockViolationAPI_GetViolations_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetViolations'
type MockViolationAPI_GetViolations_Call struct {
	*mock.Call
}

// GetViolations is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockViolationAPI_Expecter) GetViolations(ctx interface{}) *MockViolationAPI_GetViolations_Call {
	return &MockViolationAPI_GetViolations_Call{Call: _e.mock.On("GetViolations", ctx)}
}

func (_c *MockViolationAPI_GetViolations_Call) Run(run func(ctx context.Context)) *MockViolationAPI_GetViolations_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockViolationAPI_GetViolations_Call) Return(_a0 ApiGetViolationsRequest) *MockViolationAPI_GetViolations_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockViolationAPI_GetViolations_Call) RunAndReturn(run func(context.Context) ApiGetViolationsRequest) *MockViolationAPI_GetViolations_Call {
	_c.Call.Return(run)
	return _c
}

// GetViolationsByComponent provides a mock function with given fields: ctx, uuid
func (_m *MockViolationAPI) GetViolationsByComponent(ctx context.Context, uuid string) ApiGetViolationsByComponentRequest {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for GetViolationsByComponent")
	}

	var r0 ApiGetViolationsByComponentRequest
	if rf, ok := ret.Get(0).(func(context.Context, string) ApiGetViolationsByComponentRequest); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(ApiGetViolationsByComponentRequest)
	}

	return r0
}

// MockViolationAPI_GetViolationsByComponent_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetViolationsByComponent'
type MockViolationAPI_GetViolationsByComponent_Call struct {
	*mock.Call
}

// GetViolationsByComponent is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
func (_e *MockViolationAPI_Expecter) GetViolationsByComponent(ctx interface{}, uuid interface{}) *MockViolationAPI_GetViolationsByComponent_Call {
	return &MockViolationAPI_GetViolationsByComponent_Call{Call: _e.mock.On("GetViolationsByComponent", ctx, uuid)}
}

func (_c *MockViolationAPI_GetViolationsByComponent_Call) Run(run func(ctx context.Context, uuid string)) *MockViolationAPI_GetViolationsByComponent_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockViolationAPI_GetViolationsByComponent_Call) Return(_a0 ApiGetViolationsByComponentRequest) *MockViolationAPI_GetViolationsByComponent_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockViolationAPI_GetViolationsByComponent_Call) RunAndReturn(run func(context.Context, string) ApiGetViolationsByComponentRequest) *MockViolationAPI_GetViolationsByComponent_Call {
	_c.Call.Return(run)
	return _c
}

// GetViolationsByComponentExecute provides a mock function with given fields: r
func (_m *MockViolationAPI) GetViolationsByComponentExecute(r ApiGetViolationsByComponentRequest) ([]PolicyViolation, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetViolationsByComponentExecute")
	}

	var r0 []PolicyViolation
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetViolationsByComponentRequest) ([]PolicyViolation, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetViolationsByComponentRequest) []PolicyViolation); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]PolicyViolation)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetViolationsByComponentRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetViolationsByComponentRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockViolationAPI_GetViolationsByComponentExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetViolationsByComponentExecute'
type MockViolationAPI_GetViolationsByComponentExecute_Call struct {
	*mock.Call
}

// GetViolationsByComponentExecute is a helper method to define mock.On call
//   - r ApiGetViolationsByComponentRequest
func (_e *MockViolationAPI_Expecter) GetViolationsByComponentExecute(r interface{}) *MockViolationAPI_GetViolationsByComponentExecute_Call {
	return &MockViolationAPI_GetViolationsByComponentExecute_Call{Call: _e.mock.On("GetViolationsByComponentExecute", r)}
}

func (_c *MockViolationAPI_GetViolationsByComponentExecute_Call) Run(run func(r ApiGetViolationsByComponentRequest)) *MockViolationAPI_GetViolationsByComponentExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetViolationsByComponentRequest))
	})
	return _c
}

func (_c *MockViolationAPI_GetViolationsByComponentExecute_Call) Return(_a0 []PolicyViolation, _a1 *http.Response, _a2 error) *MockViolationAPI_GetViolationsByComponentExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockViolationAPI_GetViolationsByComponentExecute_Call) RunAndReturn(run func(ApiGetViolationsByComponentRequest) ([]PolicyViolation, *http.Response, error)) *MockViolationAPI_GetViolationsByComponentExecute_Call {
	_c.Call.Return(run)
	return _c
}

// GetViolationsByProject provides a mock function with given fields: ctx, uuid
func (_m *MockViolationAPI) GetViolationsByProject(ctx context.Context, uuid string) ApiGetViolationsByProjectRequest {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for GetViolationsByProject")
	}

	var r0 ApiGetViolationsByProjectRequest
	if rf, ok := ret.Get(0).(func(context.Context, string) ApiGetViolationsByProjectRequest); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(ApiGetViolationsByProjectRequest)
	}

	return r0
}

// MockViolationAPI_GetViolationsByProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetViolationsByProject'
type MockViolationAPI_GetViolationsByProject_Call struct {
	*mock.Call
}

// GetViolationsByProject is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
func (_e *MockViolationAPI_Expecter) GetViolationsByProject(ctx interface{}, uuid interface{}) *MockViolationAPI_GetViolationsByProject_Call {
	return &MockViolationAPI_GetViolationsByProject_Call{Call: _e.mock.On("GetViolationsByProject", ctx, uuid)}
}

func (_c *MockViolationAPI_GetViolationsByProject_Call) Run(run func(ctx context.Context, uuid string)) *MockViolationAPI_GetViolationsByProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockViolationAPI_GetViolationsByProject_Call) Return(_a0 ApiGetViolationsByProjectRequest) *MockViolationAPI_GetViolationsByProject_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockViolationAPI_GetViolationsByProject_Call) RunAndReturn(run func(context.Context, string) ApiGetViolationsByProjectRequest) *MockViolationAPI_GetViolationsByProject_Call {
	_c.Call.Return(run)
	return _c
}

// GetViolationsByProjectExecute provides a mock function with given fields: r
func (_m *MockViolationAPI) GetViolationsByProjectExecute(r ApiGetViolationsByProjectRequest) ([]PolicyViolation, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetViolationsByProjectExecute")
	}

	var r0 []PolicyViolation
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetViolationsByProjectRequest) ([]PolicyViolation, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetViolationsByProjectRequest) []PolicyViolation); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]PolicyViolation)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetViolationsByProjectRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetViolationsByProjectRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockViolationAPI_GetViolationsByProjectExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetViolationsByProjectExecute'
type MockViolationAPI_GetViolationsByProjectExecute_Call struct {
	*mock.Call
}

// GetViolationsByProjectExecute is a helper method to define mock.On call
//   - r ApiGetViolationsByProjectRequest
func (_e *MockViolationAPI_Expecter) GetViolationsByProjectExecute(r interface{}) *MockViolationAPI_GetViolationsByProjectExecute_Call {
	return &MockViolationAPI_GetViolationsByProjectExecute_Call{Call: _e.mock.On("GetViolationsByProjectExecute", r)}
}

func (_c *MockViolationAPI_GetViolationsByProjectExecute_Call) Run(run func(r ApiGetViolationsByProjectRequest)) *MockViolationAPI_GetViolationsByProjectExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetViolationsByProjectRequest))
	})
	return _c
}

func (_c *MockViolationAPI_GetViolationsByProjectExecute_Call) Return(_a0 []PolicyViolation, _a1 *http.Response, _a2 error) *MockViolationAPI_GetViolationsByProjectExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockViolationAPI_GetViolationsByProjectExecute_Call) RunAndReturn(run func(ApiGetViolationsByProjectRequest) ([]PolicyViolation, *http.Response, error)) *MockViolationAPI_GetViolationsByProjectExecute_Call {
	_c.Call.Return(run)
	return _c
}

// GetViolationsExecute provides a mock function with given fields: r
func (_m *MockViolationAPI) GetViolationsExecute(r ApiGetViolationsRequest) ([]PolicyViolation, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetViolationsExecute")
	}

	var r0 []PolicyViolation
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetViolationsRequest) ([]PolicyViolation, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetViolationsRequest) []PolicyViolation); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]PolicyViolation)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetViolationsRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetViolationsRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockViolationAPI_GetViolationsExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetViolationsExecute'
type MockViolationAPI_GetViolationsExecute_Call struct {
	*mock.Call
}

// GetViolationsExecute is a helper method to define mock.On call
//   - r ApiGetViolationsRequest
func (_e *MockViolationAPI_Expecter) GetViolationsExecute(r interface{}) *MockViolationAPI_GetViolationsExecute_Call {
	return &MockViolationAPI_GetViolationsExecute_Call{Call: _e.mock.On("GetViolationsExecute", r)}
}

func (_c *MockViolationAPI_GetViolationsExecute_Call) Run(run func(r ApiGetViolationsRequest)) *MockViolationAPI_GetViolationsExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetViolationsRequest))
	})
	return _c
}

func (_c *MockViolationAPI_GetViolationsExecute_Call) Return(_a0 []PolicyViolation, _a1 *http.Response, _a2 error) *MockViolationAPI_GetViolationsExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockViolationAPI_GetViolationsExecute_Call) RunAndReturn(run func(ApiGetViolationsRequest) ([]PolicyViolation, *http.Response, error)) *MockViolationAPI_GetViolationsExecute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockViolationAPI creates a new instance of MockViolationAPI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockViolationAPI(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockViolationAPI {
	mock := &MockViolationAPI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
