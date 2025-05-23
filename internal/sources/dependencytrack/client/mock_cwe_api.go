// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"
	http "net/http"

	mock "github.com/stretchr/testify/mock"
)

// MockCweAPI is an autogenerated mock type for the CweAPI type
type MockCweAPI struct {
	mock.Mock
}

type MockCweAPI_Expecter struct {
	mock *mock.Mock
}

func (_m *MockCweAPI) EXPECT() *MockCweAPI_Expecter {
	return &MockCweAPI_Expecter{mock: &_m.Mock}
}

// GetCwe provides a mock function with given fields: ctx, cweId
func (_m *MockCweAPI) GetCwe(ctx context.Context, cweId int32) ApiGetCweRequest {
	ret := _m.Called(ctx, cweId)

	if len(ret) == 0 {
		panic("no return value specified for GetCwe")
	}

	var r0 ApiGetCweRequest
	if rf, ok := ret.Get(0).(func(context.Context, int32) ApiGetCweRequest); ok {
		r0 = rf(ctx, cweId)
	} else {
		r0 = ret.Get(0).(ApiGetCweRequest)
	}

	return r0
}

// MockCweAPI_GetCwe_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCwe'
type MockCweAPI_GetCwe_Call struct {
	*mock.Call
}

// GetCwe is a helper method to define mock.On call
//   - ctx context.Context
//   - cweId int32
func (_e *MockCweAPI_Expecter) GetCwe(ctx interface{}, cweId interface{}) *MockCweAPI_GetCwe_Call {
	return &MockCweAPI_GetCwe_Call{Call: _e.mock.On("GetCwe", ctx, cweId)}
}

func (_c *MockCweAPI_GetCwe_Call) Run(run func(ctx context.Context, cweId int32)) *MockCweAPI_GetCwe_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(int32))
	})
	return _c
}

func (_c *MockCweAPI_GetCwe_Call) Return(_a0 ApiGetCweRequest) *MockCweAPI_GetCwe_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockCweAPI_GetCwe_Call) RunAndReturn(run func(context.Context, int32) ApiGetCweRequest) *MockCweAPI_GetCwe_Call {
	_c.Call.Return(run)
	return _c
}

// GetCweExecute provides a mock function with given fields: r
func (_m *MockCweAPI) GetCweExecute(r ApiGetCweRequest) (*Cwe, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetCweExecute")
	}

	var r0 *Cwe
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetCweRequest) (*Cwe, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetCweRequest) *Cwe); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Cwe)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetCweRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetCweRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockCweAPI_GetCweExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCweExecute'
type MockCweAPI_GetCweExecute_Call struct {
	*mock.Call
}

// GetCweExecute is a helper method to define mock.On call
//   - r ApiGetCweRequest
func (_e *MockCweAPI_Expecter) GetCweExecute(r interface{}) *MockCweAPI_GetCweExecute_Call {
	return &MockCweAPI_GetCweExecute_Call{Call: _e.mock.On("GetCweExecute", r)}
}

func (_c *MockCweAPI_GetCweExecute_Call) Run(run func(r ApiGetCweRequest)) *MockCweAPI_GetCweExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetCweRequest))
	})
	return _c
}

func (_c *MockCweAPI_GetCweExecute_Call) Return(_a0 *Cwe, _a1 *http.Response, _a2 error) *MockCweAPI_GetCweExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockCweAPI_GetCweExecute_Call) RunAndReturn(run func(ApiGetCweRequest) (*Cwe, *http.Response, error)) *MockCweAPI_GetCweExecute_Call {
	_c.Call.Return(run)
	return _c
}

// GetCwes provides a mock function with given fields: ctx
func (_m *MockCweAPI) GetCwes(ctx context.Context) ApiGetCwesRequest {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetCwes")
	}

	var r0 ApiGetCwesRequest
	if rf, ok := ret.Get(0).(func(context.Context) ApiGetCwesRequest); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(ApiGetCwesRequest)
	}

	return r0
}

// MockCweAPI_GetCwes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCwes'
type MockCweAPI_GetCwes_Call struct {
	*mock.Call
}

// GetCwes is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockCweAPI_Expecter) GetCwes(ctx interface{}) *MockCweAPI_GetCwes_Call {
	return &MockCweAPI_GetCwes_Call{Call: _e.mock.On("GetCwes", ctx)}
}

func (_c *MockCweAPI_GetCwes_Call) Run(run func(ctx context.Context)) *MockCweAPI_GetCwes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockCweAPI_GetCwes_Call) Return(_a0 ApiGetCwesRequest) *MockCweAPI_GetCwes_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockCweAPI_GetCwes_Call) RunAndReturn(run func(context.Context) ApiGetCwesRequest) *MockCweAPI_GetCwes_Call {
	_c.Call.Return(run)
	return _c
}

// GetCwesExecute provides a mock function with given fields: r
func (_m *MockCweAPI) GetCwesExecute(r ApiGetCwesRequest) ([]Cwe, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetCwesExecute")
	}

	var r0 []Cwe
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetCwesRequest) ([]Cwe, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetCwesRequest) []Cwe); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]Cwe)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetCwesRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetCwesRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockCweAPI_GetCwesExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCwesExecute'
type MockCweAPI_GetCwesExecute_Call struct {
	*mock.Call
}

// GetCwesExecute is a helper method to define mock.On call
//   - r ApiGetCwesRequest
func (_e *MockCweAPI_Expecter) GetCwesExecute(r interface{}) *MockCweAPI_GetCwesExecute_Call {
	return &MockCweAPI_GetCwesExecute_Call{Call: _e.mock.On("GetCwesExecute", r)}
}

func (_c *MockCweAPI_GetCwesExecute_Call) Run(run func(r ApiGetCwesRequest)) *MockCweAPI_GetCwesExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetCwesRequest))
	})
	return _c
}

func (_c *MockCweAPI_GetCwesExecute_Call) Return(_a0 []Cwe, _a1 *http.Response, _a2 error) *MockCweAPI_GetCwesExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockCweAPI_GetCwesExecute_Call) RunAndReturn(run func(ApiGetCwesRequest) ([]Cwe, *http.Response, error)) *MockCweAPI_GetCwesExecute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockCweAPI creates a new instance of MockCweAPI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockCweAPI(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockCweAPI {
	mock := &MockCweAPI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
