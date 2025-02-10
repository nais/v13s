// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"
	http "net/http"

	mock "github.com/stretchr/testify/mock"
)

// MockComponentPropertyAPI is an autogenerated mock type for the ComponentPropertyAPI type
type MockComponentPropertyAPI struct {
	mock.Mock
}

type MockComponentPropertyAPI_Expecter struct {
	mock *mock.Mock
}

func (_m *MockComponentPropertyAPI) EXPECT() *MockComponentPropertyAPI_Expecter {
	return &MockComponentPropertyAPI_Expecter{mock: &_m.Mock}
}

// CreateProperty provides a mock function with given fields: ctx, uuid
func (_m *MockComponentPropertyAPI) CreateProperty(ctx context.Context, uuid string) ApiCreatePropertyRequest {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for CreateProperty")
	}

	var r0 ApiCreatePropertyRequest
	if rf, ok := ret.Get(0).(func(context.Context, string) ApiCreatePropertyRequest); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(ApiCreatePropertyRequest)
	}

	return r0
}

// MockComponentPropertyAPI_CreateProperty_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateProperty'
type MockComponentPropertyAPI_CreateProperty_Call struct {
	*mock.Call
}

// CreateProperty is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
func (_e *MockComponentPropertyAPI_Expecter) CreateProperty(ctx interface{}, uuid interface{}) *MockComponentPropertyAPI_CreateProperty_Call {
	return &MockComponentPropertyAPI_CreateProperty_Call{Call: _e.mock.On("CreateProperty", ctx, uuid)}
}

func (_c *MockComponentPropertyAPI_CreateProperty_Call) Run(run func(ctx context.Context, uuid string)) *MockComponentPropertyAPI_CreateProperty_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockComponentPropertyAPI_CreateProperty_Call) Return(_a0 ApiCreatePropertyRequest) *MockComponentPropertyAPI_CreateProperty_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockComponentPropertyAPI_CreateProperty_Call) RunAndReturn(run func(context.Context, string) ApiCreatePropertyRequest) *MockComponentPropertyAPI_CreateProperty_Call {
	_c.Call.Return(run)
	return _c
}

// CreatePropertyExecute provides a mock function with given fields: r
func (_m *MockComponentPropertyAPI) CreatePropertyExecute(r ApiCreatePropertyRequest) (*ComponentProperty, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for CreatePropertyExecute")
	}

	var r0 *ComponentProperty
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiCreatePropertyRequest) (*ComponentProperty, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiCreatePropertyRequest) *ComponentProperty); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ComponentProperty)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiCreatePropertyRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiCreatePropertyRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockComponentPropertyAPI_CreatePropertyExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreatePropertyExecute'
type MockComponentPropertyAPI_CreatePropertyExecute_Call struct {
	*mock.Call
}

// CreatePropertyExecute is a helper method to define mock.On call
//   - r ApiCreatePropertyRequest
func (_e *MockComponentPropertyAPI_Expecter) CreatePropertyExecute(r interface{}) *MockComponentPropertyAPI_CreatePropertyExecute_Call {
	return &MockComponentPropertyAPI_CreatePropertyExecute_Call{Call: _e.mock.On("CreatePropertyExecute", r)}
}

func (_c *MockComponentPropertyAPI_CreatePropertyExecute_Call) Run(run func(r ApiCreatePropertyRequest)) *MockComponentPropertyAPI_CreatePropertyExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiCreatePropertyRequest))
	})
	return _c
}

func (_c *MockComponentPropertyAPI_CreatePropertyExecute_Call) Return(_a0 *ComponentProperty, _a1 *http.Response, _a2 error) *MockComponentPropertyAPI_CreatePropertyExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockComponentPropertyAPI_CreatePropertyExecute_Call) RunAndReturn(run func(ApiCreatePropertyRequest) (*ComponentProperty, *http.Response, error)) *MockComponentPropertyAPI_CreatePropertyExecute_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteProperty provides a mock function with given fields: ctx, uuid, propertyUuid
func (_m *MockComponentPropertyAPI) DeleteProperty(ctx context.Context, uuid string, propertyUuid string) ApiDeletePropertyRequest {
	ret := _m.Called(ctx, uuid, propertyUuid)

	if len(ret) == 0 {
		panic("no return value specified for DeleteProperty")
	}

	var r0 ApiDeletePropertyRequest
	if rf, ok := ret.Get(0).(func(context.Context, string, string) ApiDeletePropertyRequest); ok {
		r0 = rf(ctx, uuid, propertyUuid)
	} else {
		r0 = ret.Get(0).(ApiDeletePropertyRequest)
	}

	return r0
}

// MockComponentPropertyAPI_DeleteProperty_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteProperty'
type MockComponentPropertyAPI_DeleteProperty_Call struct {
	*mock.Call
}

// DeleteProperty is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
//   - propertyUuid string
func (_e *MockComponentPropertyAPI_Expecter) DeleteProperty(ctx interface{}, uuid interface{}, propertyUuid interface{}) *MockComponentPropertyAPI_DeleteProperty_Call {
	return &MockComponentPropertyAPI_DeleteProperty_Call{Call: _e.mock.On("DeleteProperty", ctx, uuid, propertyUuid)}
}

func (_c *MockComponentPropertyAPI_DeleteProperty_Call) Run(run func(ctx context.Context, uuid string, propertyUuid string)) *MockComponentPropertyAPI_DeleteProperty_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockComponentPropertyAPI_DeleteProperty_Call) Return(_a0 ApiDeletePropertyRequest) *MockComponentPropertyAPI_DeleteProperty_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockComponentPropertyAPI_DeleteProperty_Call) RunAndReturn(run func(context.Context, string, string) ApiDeletePropertyRequest) *MockComponentPropertyAPI_DeleteProperty_Call {
	_c.Call.Return(run)
	return _c
}

// DeletePropertyExecute provides a mock function with given fields: r
func (_m *MockComponentPropertyAPI) DeletePropertyExecute(r ApiDeletePropertyRequest) (*ComponentProperty, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for DeletePropertyExecute")
	}

	var r0 *ComponentProperty
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiDeletePropertyRequest) (*ComponentProperty, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiDeletePropertyRequest) *ComponentProperty); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ComponentProperty)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiDeletePropertyRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiDeletePropertyRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockComponentPropertyAPI_DeletePropertyExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeletePropertyExecute'
type MockComponentPropertyAPI_DeletePropertyExecute_Call struct {
	*mock.Call
}

// DeletePropertyExecute is a helper method to define mock.On call
//   - r ApiDeletePropertyRequest
func (_e *MockComponentPropertyAPI_Expecter) DeletePropertyExecute(r interface{}) *MockComponentPropertyAPI_DeletePropertyExecute_Call {
	return &MockComponentPropertyAPI_DeletePropertyExecute_Call{Call: _e.mock.On("DeletePropertyExecute", r)}
}

func (_c *MockComponentPropertyAPI_DeletePropertyExecute_Call) Run(run func(r ApiDeletePropertyRequest)) *MockComponentPropertyAPI_DeletePropertyExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiDeletePropertyRequest))
	})
	return _c
}

func (_c *MockComponentPropertyAPI_DeletePropertyExecute_Call) Return(_a0 *ComponentProperty, _a1 *http.Response, _a2 error) *MockComponentPropertyAPI_DeletePropertyExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockComponentPropertyAPI_DeletePropertyExecute_Call) RunAndReturn(run func(ApiDeletePropertyRequest) (*ComponentProperty, *http.Response, error)) *MockComponentPropertyAPI_DeletePropertyExecute_Call {
	_c.Call.Return(run)
	return _c
}

// GetProperties provides a mock function with given fields: ctx, uuid
func (_m *MockComponentPropertyAPI) GetProperties(ctx context.Context, uuid string) ApiGetPropertiesRequest {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for GetProperties")
	}

	var r0 ApiGetPropertiesRequest
	if rf, ok := ret.Get(0).(func(context.Context, string) ApiGetPropertiesRequest); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(ApiGetPropertiesRequest)
	}

	return r0
}

// MockComponentPropertyAPI_GetProperties_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProperties'
type MockComponentPropertyAPI_GetProperties_Call struct {
	*mock.Call
}

// GetProperties is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
func (_e *MockComponentPropertyAPI_Expecter) GetProperties(ctx interface{}, uuid interface{}) *MockComponentPropertyAPI_GetProperties_Call {
	return &MockComponentPropertyAPI_GetProperties_Call{Call: _e.mock.On("GetProperties", ctx, uuid)}
}

func (_c *MockComponentPropertyAPI_GetProperties_Call) Run(run func(ctx context.Context, uuid string)) *MockComponentPropertyAPI_GetProperties_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockComponentPropertyAPI_GetProperties_Call) Return(_a0 ApiGetPropertiesRequest) *MockComponentPropertyAPI_GetProperties_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockComponentPropertyAPI_GetProperties_Call) RunAndReturn(run func(context.Context, string) ApiGetPropertiesRequest) *MockComponentPropertyAPI_GetProperties_Call {
	_c.Call.Return(run)
	return _c
}

// GetPropertiesExecute provides a mock function with given fields: r
func (_m *MockComponentPropertyAPI) GetPropertiesExecute(r ApiGetPropertiesRequest) ([]ComponentProperty, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetPropertiesExecute")
	}

	var r0 []ComponentProperty
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetPropertiesRequest) ([]ComponentProperty, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetPropertiesRequest) []ComponentProperty); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]ComponentProperty)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetPropertiesRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetPropertiesRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockComponentPropertyAPI_GetPropertiesExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetPropertiesExecute'
type MockComponentPropertyAPI_GetPropertiesExecute_Call struct {
	*mock.Call
}

// GetPropertiesExecute is a helper method to define mock.On call
//   - r ApiGetPropertiesRequest
func (_e *MockComponentPropertyAPI_Expecter) GetPropertiesExecute(r interface{}) *MockComponentPropertyAPI_GetPropertiesExecute_Call {
	return &MockComponentPropertyAPI_GetPropertiesExecute_Call{Call: _e.mock.On("GetPropertiesExecute", r)}
}

func (_c *MockComponentPropertyAPI_GetPropertiesExecute_Call) Run(run func(r ApiGetPropertiesRequest)) *MockComponentPropertyAPI_GetPropertiesExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetPropertiesRequest))
	})
	return _c
}

func (_c *MockComponentPropertyAPI_GetPropertiesExecute_Call) Return(_a0 []ComponentProperty, _a1 *http.Response, _a2 error) *MockComponentPropertyAPI_GetPropertiesExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockComponentPropertyAPI_GetPropertiesExecute_Call) RunAndReturn(run func(ApiGetPropertiesRequest) ([]ComponentProperty, *http.Response, error)) *MockComponentPropertyAPI_GetPropertiesExecute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockComponentPropertyAPI creates a new instance of MockComponentPropertyAPI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockComponentPropertyAPI(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockComponentPropertyAPI {
	mock := &MockComponentPropertyAPI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
