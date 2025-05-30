// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"
	http "net/http"

	mock "github.com/stretchr/testify/mock"
)

// MockRepositoryAPI is an autogenerated mock type for the RepositoryAPI type
type MockRepositoryAPI struct {
	mock.Mock
}

type MockRepositoryAPI_Expecter struct {
	mock *mock.Mock
}

func (_m *MockRepositoryAPI) EXPECT() *MockRepositoryAPI_Expecter {
	return &MockRepositoryAPI_Expecter{mock: &_m.Mock}
}

// CreateRepository provides a mock function with given fields: ctx
func (_m *MockRepositoryAPI) CreateRepository(ctx context.Context) ApiCreateRepositoryRequest {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for CreateRepository")
	}

	var r0 ApiCreateRepositoryRequest
	if rf, ok := ret.Get(0).(func(context.Context) ApiCreateRepositoryRequest); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(ApiCreateRepositoryRequest)
	}

	return r0
}

// MockRepositoryAPI_CreateRepository_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateRepository'
type MockRepositoryAPI_CreateRepository_Call struct {
	*mock.Call
}

// CreateRepository is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockRepositoryAPI_Expecter) CreateRepository(ctx interface{}) *MockRepositoryAPI_CreateRepository_Call {
	return &MockRepositoryAPI_CreateRepository_Call{Call: _e.mock.On("CreateRepository", ctx)}
}

func (_c *MockRepositoryAPI_CreateRepository_Call) Run(run func(ctx context.Context)) *MockRepositoryAPI_CreateRepository_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockRepositoryAPI_CreateRepository_Call) Return(_a0 ApiCreateRepositoryRequest) *MockRepositoryAPI_CreateRepository_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositoryAPI_CreateRepository_Call) RunAndReturn(run func(context.Context) ApiCreateRepositoryRequest) *MockRepositoryAPI_CreateRepository_Call {
	_c.Call.Return(run)
	return _c
}

// CreateRepositoryExecute provides a mock function with given fields: r
func (_m *MockRepositoryAPI) CreateRepositoryExecute(r ApiCreateRepositoryRequest) (*Repository, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for CreateRepositoryExecute")
	}

	var r0 *Repository
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiCreateRepositoryRequest) (*Repository, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiCreateRepositoryRequest) *Repository); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Repository)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiCreateRepositoryRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiCreateRepositoryRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockRepositoryAPI_CreateRepositoryExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateRepositoryExecute'
type MockRepositoryAPI_CreateRepositoryExecute_Call struct {
	*mock.Call
}

// CreateRepositoryExecute is a helper method to define mock.On call
//   - r ApiCreateRepositoryRequest
func (_e *MockRepositoryAPI_Expecter) CreateRepositoryExecute(r interface{}) *MockRepositoryAPI_CreateRepositoryExecute_Call {
	return &MockRepositoryAPI_CreateRepositoryExecute_Call{Call: _e.mock.On("CreateRepositoryExecute", r)}
}

func (_c *MockRepositoryAPI_CreateRepositoryExecute_Call) Run(run func(r ApiCreateRepositoryRequest)) *MockRepositoryAPI_CreateRepositoryExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiCreateRepositoryRequest))
	})
	return _c
}

func (_c *MockRepositoryAPI_CreateRepositoryExecute_Call) Return(_a0 *Repository, _a1 *http.Response, _a2 error) *MockRepositoryAPI_CreateRepositoryExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockRepositoryAPI_CreateRepositoryExecute_Call) RunAndReturn(run func(ApiCreateRepositoryRequest) (*Repository, *http.Response, error)) *MockRepositoryAPI_CreateRepositoryExecute_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteRepository provides a mock function with given fields: ctx, uuid
func (_m *MockRepositoryAPI) DeleteRepository(ctx context.Context, uuid string) ApiDeleteRepositoryRequest {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for DeleteRepository")
	}

	var r0 ApiDeleteRepositoryRequest
	if rf, ok := ret.Get(0).(func(context.Context, string) ApiDeleteRepositoryRequest); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(ApiDeleteRepositoryRequest)
	}

	return r0
}

// MockRepositoryAPI_DeleteRepository_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteRepository'
type MockRepositoryAPI_DeleteRepository_Call struct {
	*mock.Call
}

// DeleteRepository is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
func (_e *MockRepositoryAPI_Expecter) DeleteRepository(ctx interface{}, uuid interface{}) *MockRepositoryAPI_DeleteRepository_Call {
	return &MockRepositoryAPI_DeleteRepository_Call{Call: _e.mock.On("DeleteRepository", ctx, uuid)}
}

func (_c *MockRepositoryAPI_DeleteRepository_Call) Run(run func(ctx context.Context, uuid string)) *MockRepositoryAPI_DeleteRepository_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockRepositoryAPI_DeleteRepository_Call) Return(_a0 ApiDeleteRepositoryRequest) *MockRepositoryAPI_DeleteRepository_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositoryAPI_DeleteRepository_Call) RunAndReturn(run func(context.Context, string) ApiDeleteRepositoryRequest) *MockRepositoryAPI_DeleteRepository_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteRepositoryExecute provides a mock function with given fields: r
func (_m *MockRepositoryAPI) DeleteRepositoryExecute(r ApiDeleteRepositoryRequest) (*http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for DeleteRepositoryExecute")
	}

	var r0 *http.Response
	var r1 error
	if rf, ok := ret.Get(0).(func(ApiDeleteRepositoryRequest) (*http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiDeleteRepositoryRequest) *http.Response); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*http.Response)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiDeleteRepositoryRequest) error); ok {
		r1 = rf(r)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockRepositoryAPI_DeleteRepositoryExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteRepositoryExecute'
type MockRepositoryAPI_DeleteRepositoryExecute_Call struct {
	*mock.Call
}

// DeleteRepositoryExecute is a helper method to define mock.On call
//   - r ApiDeleteRepositoryRequest
func (_e *MockRepositoryAPI_Expecter) DeleteRepositoryExecute(r interface{}) *MockRepositoryAPI_DeleteRepositoryExecute_Call {
	return &MockRepositoryAPI_DeleteRepositoryExecute_Call{Call: _e.mock.On("DeleteRepositoryExecute", r)}
}

func (_c *MockRepositoryAPI_DeleteRepositoryExecute_Call) Run(run func(r ApiDeleteRepositoryRequest)) *MockRepositoryAPI_DeleteRepositoryExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiDeleteRepositoryRequest))
	})
	return _c
}

func (_c *MockRepositoryAPI_DeleteRepositoryExecute_Call) Return(_a0 *http.Response, _a1 error) *MockRepositoryAPI_DeleteRepositoryExecute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockRepositoryAPI_DeleteRepositoryExecute_Call) RunAndReturn(run func(ApiDeleteRepositoryRequest) (*http.Response, error)) *MockRepositoryAPI_DeleteRepositoryExecute_Call {
	_c.Call.Return(run)
	return _c
}

// GetRepositories provides a mock function with given fields: ctx
func (_m *MockRepositoryAPI) GetRepositories(ctx context.Context) ApiGetRepositoriesRequest {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetRepositories")
	}

	var r0 ApiGetRepositoriesRequest
	if rf, ok := ret.Get(0).(func(context.Context) ApiGetRepositoriesRequest); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(ApiGetRepositoriesRequest)
	}

	return r0
}

// MockRepositoryAPI_GetRepositories_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRepositories'
type MockRepositoryAPI_GetRepositories_Call struct {
	*mock.Call
}

// GetRepositories is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockRepositoryAPI_Expecter) GetRepositories(ctx interface{}) *MockRepositoryAPI_GetRepositories_Call {
	return &MockRepositoryAPI_GetRepositories_Call{Call: _e.mock.On("GetRepositories", ctx)}
}

func (_c *MockRepositoryAPI_GetRepositories_Call) Run(run func(ctx context.Context)) *MockRepositoryAPI_GetRepositories_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockRepositoryAPI_GetRepositories_Call) Return(_a0 ApiGetRepositoriesRequest) *MockRepositoryAPI_GetRepositories_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositoryAPI_GetRepositories_Call) RunAndReturn(run func(context.Context) ApiGetRepositoriesRequest) *MockRepositoryAPI_GetRepositories_Call {
	_c.Call.Return(run)
	return _c
}

// GetRepositoriesByType provides a mock function with given fields: ctx, type_
func (_m *MockRepositoryAPI) GetRepositoriesByType(ctx context.Context, type_ string) ApiGetRepositoriesByTypeRequest {
	ret := _m.Called(ctx, type_)

	if len(ret) == 0 {
		panic("no return value specified for GetRepositoriesByType")
	}

	var r0 ApiGetRepositoriesByTypeRequest
	if rf, ok := ret.Get(0).(func(context.Context, string) ApiGetRepositoriesByTypeRequest); ok {
		r0 = rf(ctx, type_)
	} else {
		r0 = ret.Get(0).(ApiGetRepositoriesByTypeRequest)
	}

	return r0
}

// MockRepositoryAPI_GetRepositoriesByType_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRepositoriesByType'
type MockRepositoryAPI_GetRepositoriesByType_Call struct {
	*mock.Call
}

// GetRepositoriesByType is a helper method to define mock.On call
//   - ctx context.Context
//   - type_ string
func (_e *MockRepositoryAPI_Expecter) GetRepositoriesByType(ctx interface{}, type_ interface{}) *MockRepositoryAPI_GetRepositoriesByType_Call {
	return &MockRepositoryAPI_GetRepositoriesByType_Call{Call: _e.mock.On("GetRepositoriesByType", ctx, type_)}
}

func (_c *MockRepositoryAPI_GetRepositoriesByType_Call) Run(run func(ctx context.Context, type_ string)) *MockRepositoryAPI_GetRepositoriesByType_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoriesByType_Call) Return(_a0 ApiGetRepositoriesByTypeRequest) *MockRepositoryAPI_GetRepositoriesByType_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoriesByType_Call) RunAndReturn(run func(context.Context, string) ApiGetRepositoriesByTypeRequest) *MockRepositoryAPI_GetRepositoriesByType_Call {
	_c.Call.Return(run)
	return _c
}

// GetRepositoriesByTypeExecute provides a mock function with given fields: r
func (_m *MockRepositoryAPI) GetRepositoriesByTypeExecute(r ApiGetRepositoriesByTypeRequest) ([]Repository, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetRepositoriesByTypeExecute")
	}

	var r0 []Repository
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetRepositoriesByTypeRequest) ([]Repository, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetRepositoriesByTypeRequest) []Repository); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]Repository)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetRepositoriesByTypeRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetRepositoriesByTypeRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockRepositoryAPI_GetRepositoriesByTypeExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRepositoriesByTypeExecute'
type MockRepositoryAPI_GetRepositoriesByTypeExecute_Call struct {
	*mock.Call
}

// GetRepositoriesByTypeExecute is a helper method to define mock.On call
//   - r ApiGetRepositoriesByTypeRequest
func (_e *MockRepositoryAPI_Expecter) GetRepositoriesByTypeExecute(r interface{}) *MockRepositoryAPI_GetRepositoriesByTypeExecute_Call {
	return &MockRepositoryAPI_GetRepositoriesByTypeExecute_Call{Call: _e.mock.On("GetRepositoriesByTypeExecute", r)}
}

func (_c *MockRepositoryAPI_GetRepositoriesByTypeExecute_Call) Run(run func(r ApiGetRepositoriesByTypeRequest)) *MockRepositoryAPI_GetRepositoriesByTypeExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetRepositoriesByTypeRequest))
	})
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoriesByTypeExecute_Call) Return(_a0 []Repository, _a1 *http.Response, _a2 error) *MockRepositoryAPI_GetRepositoriesByTypeExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoriesByTypeExecute_Call) RunAndReturn(run func(ApiGetRepositoriesByTypeRequest) ([]Repository, *http.Response, error)) *MockRepositoryAPI_GetRepositoriesByTypeExecute_Call {
	_c.Call.Return(run)
	return _c
}

// GetRepositoriesExecute provides a mock function with given fields: r
func (_m *MockRepositoryAPI) GetRepositoriesExecute(r ApiGetRepositoriesRequest) ([]Repository, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetRepositoriesExecute")
	}

	var r0 []Repository
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetRepositoriesRequest) ([]Repository, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetRepositoriesRequest) []Repository); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]Repository)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetRepositoriesRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetRepositoriesRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockRepositoryAPI_GetRepositoriesExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRepositoriesExecute'
type MockRepositoryAPI_GetRepositoriesExecute_Call struct {
	*mock.Call
}

// GetRepositoriesExecute is a helper method to define mock.On call
//   - r ApiGetRepositoriesRequest
func (_e *MockRepositoryAPI_Expecter) GetRepositoriesExecute(r interface{}) *MockRepositoryAPI_GetRepositoriesExecute_Call {
	return &MockRepositoryAPI_GetRepositoriesExecute_Call{Call: _e.mock.On("GetRepositoriesExecute", r)}
}

func (_c *MockRepositoryAPI_GetRepositoriesExecute_Call) Run(run func(r ApiGetRepositoriesRequest)) *MockRepositoryAPI_GetRepositoriesExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetRepositoriesRequest))
	})
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoriesExecute_Call) Return(_a0 []Repository, _a1 *http.Response, _a2 error) *MockRepositoryAPI_GetRepositoriesExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoriesExecute_Call) RunAndReturn(run func(ApiGetRepositoriesRequest) ([]Repository, *http.Response, error)) *MockRepositoryAPI_GetRepositoriesExecute_Call {
	_c.Call.Return(run)
	return _c
}

// GetRepositoryMetaComponent provides a mock function with given fields: ctx
func (_m *MockRepositoryAPI) GetRepositoryMetaComponent(ctx context.Context) ApiGetRepositoryMetaComponentRequest {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetRepositoryMetaComponent")
	}

	var r0 ApiGetRepositoryMetaComponentRequest
	if rf, ok := ret.Get(0).(func(context.Context) ApiGetRepositoryMetaComponentRequest); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(ApiGetRepositoryMetaComponentRequest)
	}

	return r0
}

// MockRepositoryAPI_GetRepositoryMetaComponent_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRepositoryMetaComponent'
type MockRepositoryAPI_GetRepositoryMetaComponent_Call struct {
	*mock.Call
}

// GetRepositoryMetaComponent is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockRepositoryAPI_Expecter) GetRepositoryMetaComponent(ctx interface{}) *MockRepositoryAPI_GetRepositoryMetaComponent_Call {
	return &MockRepositoryAPI_GetRepositoryMetaComponent_Call{Call: _e.mock.On("GetRepositoryMetaComponent", ctx)}
}

func (_c *MockRepositoryAPI_GetRepositoryMetaComponent_Call) Run(run func(ctx context.Context)) *MockRepositoryAPI_GetRepositoryMetaComponent_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoryMetaComponent_Call) Return(_a0 ApiGetRepositoryMetaComponentRequest) *MockRepositoryAPI_GetRepositoryMetaComponent_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoryMetaComponent_Call) RunAndReturn(run func(context.Context) ApiGetRepositoryMetaComponentRequest) *MockRepositoryAPI_GetRepositoryMetaComponent_Call {
	_c.Call.Return(run)
	return _c
}

// GetRepositoryMetaComponentExecute provides a mock function with given fields: r
func (_m *MockRepositoryAPI) GetRepositoryMetaComponentExecute(r ApiGetRepositoryMetaComponentRequest) (*RepositoryMetaComponent, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetRepositoryMetaComponentExecute")
	}

	var r0 *RepositoryMetaComponent
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiGetRepositoryMetaComponentRequest) (*RepositoryMetaComponent, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiGetRepositoryMetaComponentRequest) *RepositoryMetaComponent); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*RepositoryMetaComponent)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiGetRepositoryMetaComponentRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiGetRepositoryMetaComponentRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRepositoryMetaComponentExecute'
type MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call struct {
	*mock.Call
}

// GetRepositoryMetaComponentExecute is a helper method to define mock.On call
//   - r ApiGetRepositoryMetaComponentRequest
func (_e *MockRepositoryAPI_Expecter) GetRepositoryMetaComponentExecute(r interface{}) *MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call {
	return &MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call{Call: _e.mock.On("GetRepositoryMetaComponentExecute", r)}
}

func (_c *MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call) Run(run func(r ApiGetRepositoryMetaComponentRequest)) *MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiGetRepositoryMetaComponentRequest))
	})
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call) Return(_a0 *RepositoryMetaComponent, _a1 *http.Response, _a2 error) *MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call) RunAndReturn(run func(ApiGetRepositoryMetaComponentRequest) (*RepositoryMetaComponent, *http.Response, error)) *MockRepositoryAPI_GetRepositoryMetaComponentExecute_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateRepository provides a mock function with given fields: ctx
func (_m *MockRepositoryAPI) UpdateRepository(ctx context.Context) ApiUpdateRepositoryRequest {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRepository")
	}

	var r0 ApiUpdateRepositoryRequest
	if rf, ok := ret.Get(0).(func(context.Context) ApiUpdateRepositoryRequest); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(ApiUpdateRepositoryRequest)
	}

	return r0
}

// MockRepositoryAPI_UpdateRepository_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateRepository'
type MockRepositoryAPI_UpdateRepository_Call struct {
	*mock.Call
}

// UpdateRepository is a helper method to define mock.On call
//   - ctx context.Context
func (_e *MockRepositoryAPI_Expecter) UpdateRepository(ctx interface{}) *MockRepositoryAPI_UpdateRepository_Call {
	return &MockRepositoryAPI_UpdateRepository_Call{Call: _e.mock.On("UpdateRepository", ctx)}
}

func (_c *MockRepositoryAPI_UpdateRepository_Call) Run(run func(ctx context.Context)) *MockRepositoryAPI_UpdateRepository_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockRepositoryAPI_UpdateRepository_Call) Return(_a0 ApiUpdateRepositoryRequest) *MockRepositoryAPI_UpdateRepository_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockRepositoryAPI_UpdateRepository_Call) RunAndReturn(run func(context.Context) ApiUpdateRepositoryRequest) *MockRepositoryAPI_UpdateRepository_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateRepositoryExecute provides a mock function with given fields: r
func (_m *MockRepositoryAPI) UpdateRepositoryExecute(r ApiUpdateRepositoryRequest) (*Repository, *http.Response, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRepositoryExecute")
	}

	var r0 *Repository
	var r1 *http.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(ApiUpdateRepositoryRequest) (*Repository, *http.Response, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(ApiUpdateRepositoryRequest) *Repository); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Repository)
		}
	}

	if rf, ok := ret.Get(1).(func(ApiUpdateRepositoryRequest) *http.Response); ok {
		r1 = rf(r)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*http.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(ApiUpdateRepositoryRequest) error); ok {
		r2 = rf(r)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockRepositoryAPI_UpdateRepositoryExecute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateRepositoryExecute'
type MockRepositoryAPI_UpdateRepositoryExecute_Call struct {
	*mock.Call
}

// UpdateRepositoryExecute is a helper method to define mock.On call
//   - r ApiUpdateRepositoryRequest
func (_e *MockRepositoryAPI_Expecter) UpdateRepositoryExecute(r interface{}) *MockRepositoryAPI_UpdateRepositoryExecute_Call {
	return &MockRepositoryAPI_UpdateRepositoryExecute_Call{Call: _e.mock.On("UpdateRepositoryExecute", r)}
}

func (_c *MockRepositoryAPI_UpdateRepositoryExecute_Call) Run(run func(r ApiUpdateRepositoryRequest)) *MockRepositoryAPI_UpdateRepositoryExecute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(ApiUpdateRepositoryRequest))
	})
	return _c
}

func (_c *MockRepositoryAPI_UpdateRepositoryExecute_Call) Return(_a0 *Repository, _a1 *http.Response, _a2 error) *MockRepositoryAPI_UpdateRepositoryExecute_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockRepositoryAPI_UpdateRepositoryExecute_Call) RunAndReturn(run func(ApiUpdateRepositoryRequest) (*Repository, *http.Response, error)) *MockRepositoryAPI_UpdateRepositoryExecute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockRepositoryAPI creates a new instance of MockRepositoryAPI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockRepositoryAPI(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockRepositoryAPI {
	mock := &MockRepositoryAPI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
