// Code generated by mockery. DO NOT EDIT.

package dependencytrack

import (
	context "context"

	client "github.com/nais/v13s/internal/sources/dependencytrack/client"

	in_toto "github.com/in-toto/in-toto-golang/in_toto"

	mock "github.com/stretchr/testify/mock"
)

// MockClient is an autogenerated mock type for the Client type
type MockClient struct {
	mock.Mock
}

type MockClient_Expecter struct {
	mock *mock.Mock
}

func (_m *MockClient) EXPECT() *MockClient_Expecter {
	return &MockClient_Expecter{mock: &_m.Mock}
}

// CreateOrUpdateProjectWithSbom provides a mock function with given fields: ctx, sbom, workloadRef
func (_m *MockClient) CreateOrUpdateProjectWithSbom(ctx context.Context, sbom *in_toto.CycloneDXStatement, workloadRef *WorkloadRef) (string, error) {
	ret := _m.Called(ctx, sbom, workloadRef)

	if len(ret) == 0 {
		panic("no return value specified for CreateOrUpdateProjectWithSbom")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *in_toto.CycloneDXStatement, *WorkloadRef) (string, error)); ok {
		return rf(ctx, sbom, workloadRef)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *in_toto.CycloneDXStatement, *WorkloadRef) string); ok {
		r0 = rf(ctx, sbom, workloadRef)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *in_toto.CycloneDXStatement, *WorkloadRef) error); ok {
		r1 = rf(ctx, sbom, workloadRef)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_CreateOrUpdateProjectWithSbom_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateOrUpdateProjectWithSbom'
type MockClient_CreateOrUpdateProjectWithSbom_Call struct {
	*mock.Call
}

// CreateOrUpdateProjectWithSbom is a helper method to define mock.On call
//   - ctx context.Context
//   - sbom *in_toto.CycloneDXStatement
//   - workloadRef *WorkloadRef
func (_e *MockClient_Expecter) CreateOrUpdateProjectWithSbom(ctx interface{}, sbom interface{}, workloadRef interface{}) *MockClient_CreateOrUpdateProjectWithSbom_Call {
	return &MockClient_CreateOrUpdateProjectWithSbom_Call{Call: _e.mock.On("CreateOrUpdateProjectWithSbom", ctx, sbom, workloadRef)}
}

func (_c *MockClient_CreateOrUpdateProjectWithSbom_Call) Run(run func(ctx context.Context, sbom *in_toto.CycloneDXStatement, workloadRef *WorkloadRef)) *MockClient_CreateOrUpdateProjectWithSbom_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*in_toto.CycloneDXStatement), args[2].(*WorkloadRef))
	})
	return _c
}

func (_c *MockClient_CreateOrUpdateProjectWithSbom_Call) Return(_a0 string, _a1 error) *MockClient_CreateOrUpdateProjectWithSbom_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_CreateOrUpdateProjectWithSbom_Call) RunAndReturn(run func(context.Context, *in_toto.CycloneDXStatement, *WorkloadRef) (string, error)) *MockClient_CreateOrUpdateProjectWithSbom_Call {
	_c.Call.Return(run)
	return _c
}

// CreateProject provides a mock function with given fields: ctx, name, version, tags
func (_m *MockClient) CreateProject(ctx context.Context, name string, version string, tags []client.Tag) (*client.Project, error) {
	ret := _m.Called(ctx, name, version, tags)

	if len(ret) == 0 {
		panic("no return value specified for CreateProject")
	}

	var r0 *client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, []client.Tag) (*client.Project, error)); ok {
		return rf(ctx, name, version, tags)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, []client.Tag) *client.Project); ok {
		r0 = rf(ctx, name, version, tags)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, []client.Tag) error); ok {
		r1 = rf(ctx, name, version, tags)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_CreateProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateProject'
type MockClient_CreateProject_Call struct {
	*mock.Call
}

// CreateProject is a helper method to define mock.On call
//   - ctx context.Context
//   - name string
//   - version string
//   - tags []client.Tag
func (_e *MockClient_Expecter) CreateProject(ctx interface{}, name interface{}, version interface{}, tags interface{}) *MockClient_CreateProject_Call {
	return &MockClient_CreateProject_Call{Call: _e.mock.On("CreateProject", ctx, name, version, tags)}
}

func (_c *MockClient_CreateProject_Call) Run(run func(ctx context.Context, name string, version string, tags []client.Tag)) *MockClient_CreateProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].([]client.Tag))
	})
	return _c
}

func (_c *MockClient_CreateProject_Call) Return(_a0 *client.Project, _a1 error) *MockClient_CreateProject_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_CreateProject_Call) RunAndReturn(run func(context.Context, string, string, []client.Tag) (*client.Project, error)) *MockClient_CreateProject_Call {
	_c.Call.Return(run)
	return _c
}

// CreateProjectWithSbom provides a mock function with given fields: ctx, sbom, imageName, imageTag
func (_m *MockClient) CreateProjectWithSbom(ctx context.Context, sbom *in_toto.CycloneDXStatement, imageName string, imageTag string) (string, error) {
	ret := _m.Called(ctx, sbom, imageName, imageTag)

	if len(ret) == 0 {
		panic("no return value specified for CreateProjectWithSbom")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *in_toto.CycloneDXStatement, string, string) (string, error)); ok {
		return rf(ctx, sbom, imageName, imageTag)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *in_toto.CycloneDXStatement, string, string) string); ok {
		r0 = rf(ctx, sbom, imageName, imageTag)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *in_toto.CycloneDXStatement, string, string) error); ok {
		r1 = rf(ctx, sbom, imageName, imageTag)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_CreateProjectWithSbom_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateProjectWithSbom'
type MockClient_CreateProjectWithSbom_Call struct {
	*mock.Call
}

// CreateProjectWithSbom is a helper method to define mock.On call
//   - ctx context.Context
//   - sbom *in_toto.CycloneDXStatement
//   - imageName string
//   - imageTag string
func (_e *MockClient_Expecter) CreateProjectWithSbom(ctx interface{}, sbom interface{}, imageName interface{}, imageTag interface{}) *MockClient_CreateProjectWithSbom_Call {
	return &MockClient_CreateProjectWithSbom_Call{Call: _e.mock.On("CreateProjectWithSbom", ctx, sbom, imageName, imageTag)}
}

func (_c *MockClient_CreateProjectWithSbom_Call) Run(run func(ctx context.Context, sbom *in_toto.CycloneDXStatement, imageName string, imageTag string)) *MockClient_CreateProjectWithSbom_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*in_toto.CycloneDXStatement), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *MockClient_CreateProjectWithSbom_Call) Return(_a0 string, _a1 error) *MockClient_CreateProjectWithSbom_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_CreateProjectWithSbom_Call) RunAndReturn(run func(context.Context, *in_toto.CycloneDXStatement, string, string) (string, error)) *MockClient_CreateProjectWithSbom_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteProject provides a mock function with given fields: ctx, uuid
func (_m *MockClient) DeleteProject(ctx context.Context, uuid string) error {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for DeleteProject")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockClient_DeleteProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteProject'
type MockClient_DeleteProject_Call struct {
	*mock.Call
}

// DeleteProject is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
func (_e *MockClient_Expecter) DeleteProject(ctx interface{}, uuid interface{}) *MockClient_DeleteProject_Call {
	return &MockClient_DeleteProject_Call{Call: _e.mock.On("DeleteProject", ctx, uuid)}
}

func (_c *MockClient_DeleteProject_Call) Run(run func(ctx context.Context, uuid string)) *MockClient_DeleteProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockClient_DeleteProject_Call) Return(_a0 error) *MockClient_DeleteProject_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockClient_DeleteProject_Call) RunAndReturn(run func(context.Context, string) error) *MockClient_DeleteProject_Call {
	_c.Call.Return(run)
	return _c
}

// GetAnalysisTrailForImage provides a mock function with given fields: ctx, projectId, componentId, vulnerabilityId
func (_m *MockClient) GetAnalysisTrailForImage(ctx context.Context, projectId string, componentId string, vulnerabilityId string) (*client.Analysis, error) {
	ret := _m.Called(ctx, projectId, componentId, vulnerabilityId)

	if len(ret) == 0 {
		panic("no return value specified for GetAnalysisTrailForImage")
	}

	var r0 *client.Analysis
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (*client.Analysis, error)); ok {
		return rf(ctx, projectId, componentId, vulnerabilityId)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) *client.Analysis); ok {
		r0 = rf(ctx, projectId, componentId, vulnerabilityId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Analysis)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, projectId, componentId, vulnerabilityId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_GetAnalysisTrailForImage_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAnalysisTrailForImage'
type MockClient_GetAnalysisTrailForImage_Call struct {
	*mock.Call
}

// GetAnalysisTrailForImage is a helper method to define mock.On call
//   - ctx context.Context
//   - projectId string
//   - componentId string
//   - vulnerabilityId string
func (_e *MockClient_Expecter) GetAnalysisTrailForImage(ctx interface{}, projectId interface{}, componentId interface{}, vulnerabilityId interface{}) *MockClient_GetAnalysisTrailForImage_Call {
	return &MockClient_GetAnalysisTrailForImage_Call{Call: _e.mock.On("GetAnalysisTrailForImage", ctx, projectId, componentId, vulnerabilityId)}
}

func (_c *MockClient_GetAnalysisTrailForImage_Call) Run(run func(ctx context.Context, projectId string, componentId string, vulnerabilityId string)) *MockClient_GetAnalysisTrailForImage_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *MockClient_GetAnalysisTrailForImage_Call) Return(_a0 *client.Analysis, _a1 error) *MockClient_GetAnalysisTrailForImage_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_GetAnalysisTrailForImage_Call) RunAndReturn(run func(context.Context, string, string, string) (*client.Analysis, error)) *MockClient_GetAnalysisTrailForImage_Call {
	_c.Call.Return(run)
	return _c
}

// GetFindings provides a mock function with given fields: ctx, uuid, vulnerabilityId, suppressed
func (_m *MockClient) GetFindings(ctx context.Context, uuid string, vulnerabilityId string, suppressed bool) ([]client.Finding, error) {
	ret := _m.Called(ctx, uuid, vulnerabilityId, suppressed)

	if len(ret) == 0 {
		panic("no return value specified for GetFindings")
	}

	var r0 []client.Finding
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, bool) ([]client.Finding, error)); ok {
		return rf(ctx, uuid, vulnerabilityId, suppressed)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, bool) []client.Finding); ok {
		r0 = rf(ctx, uuid, vulnerabilityId, suppressed)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]client.Finding)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, bool) error); ok {
		r1 = rf(ctx, uuid, vulnerabilityId, suppressed)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_GetFindings_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFindings'
type MockClient_GetFindings_Call struct {
	*mock.Call
}

// GetFindings is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
//   - vulnerabilityId string
//   - suppressed bool
func (_e *MockClient_Expecter) GetFindings(ctx interface{}, uuid interface{}, vulnerabilityId interface{}, suppressed interface{}) *MockClient_GetFindings_Call {
	return &MockClient_GetFindings_Call{Call: _e.mock.On("GetFindings", ctx, uuid, vulnerabilityId, suppressed)}
}

func (_c *MockClient_GetFindings_Call) Run(run func(ctx context.Context, uuid string, vulnerabilityId string, suppressed bool)) *MockClient_GetFindings_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(bool))
	})
	return _c
}

func (_c *MockClient_GetFindings_Call) Return(_a0 []client.Finding, _a1 error) *MockClient_GetFindings_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_GetFindings_Call) RunAndReturn(run func(context.Context, string, string, bool) ([]client.Finding, error)) *MockClient_GetFindings_Call {
	_c.Call.Return(run)
	return _c
}

// GetProject provides a mock function with given fields: ctx, name, version
func (_m *MockClient) GetProject(ctx context.Context, name string, version string) (*client.Project, error) {
	ret := _m.Called(ctx, name, version)

	if len(ret) == 0 {
		panic("no return value specified for GetProject")
	}

	var r0 *client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (*client.Project, error)); ok {
		return rf(ctx, name, version)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *client.Project); ok {
		r0 = rf(ctx, name, version)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, name, version)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_GetProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProject'
type MockClient_GetProject_Call struct {
	*mock.Call
}

// GetProject is a helper method to define mock.On call
//   - ctx context.Context
//   - name string
//   - version string
func (_e *MockClient_Expecter) GetProject(ctx interface{}, name interface{}, version interface{}) *MockClient_GetProject_Call {
	return &MockClient_GetProject_Call{Call: _e.mock.On("GetProject", ctx, name, version)}
}

func (_c *MockClient_GetProject_Call) Run(run func(ctx context.Context, name string, version string)) *MockClient_GetProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockClient_GetProject_Call) Return(_a0 *client.Project, _a1 error) *MockClient_GetProject_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_GetProject_Call) RunAndReturn(run func(context.Context, string, string) (*client.Project, error)) *MockClient_GetProject_Call {
	_c.Call.Return(run)
	return _c
}

// GetProjects provides a mock function with given fields: ctx, limit, offset
func (_m *MockClient) GetProjects(ctx context.Context, limit int32, offset int32) ([]client.Project, error) {
	ret := _m.Called(ctx, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for GetProjects")
	}

	var r0 []client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, int32, int32) ([]client.Project, error)); ok {
		return rf(ctx, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, int32, int32) []client.Project); ok {
		r0 = rf(ctx, limit, offset)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, int32, int32) error); ok {
		r1 = rf(ctx, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_GetProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProjects'
type MockClient_GetProjects_Call struct {
	*mock.Call
}

// GetProjects is a helper method to define mock.On call
//   - ctx context.Context
//   - limit int32
//   - offset int32
func (_e *MockClient_Expecter) GetProjects(ctx interface{}, limit interface{}, offset interface{}) *MockClient_GetProjects_Call {
	return &MockClient_GetProjects_Call{Call: _e.mock.On("GetProjects", ctx, limit, offset)}
}

func (_c *MockClient_GetProjects_Call) Run(run func(ctx context.Context, limit int32, offset int32)) *MockClient_GetProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(int32), args[2].(int32))
	})
	return _c
}

func (_c *MockClient_GetProjects_Call) Return(_a0 []client.Project, _a1 error) *MockClient_GetProjects_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_GetProjects_Call) RunAndReturn(run func(context.Context, int32, int32) ([]client.Project, error)) *MockClient_GetProjects_Call {
	_c.Call.Return(run)
	return _c
}

// GetProjectsByTag provides a mock function with given fields: ctx, tag, limit, offset
func (_m *MockClient) GetProjectsByTag(ctx context.Context, tag string, limit int32, offset int32) ([]client.Project, error) {
	ret := _m.Called(ctx, tag, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for GetProjectsByTag")
	}

	var r0 []client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, int32, int32) ([]client.Project, error)); ok {
		return rf(ctx, tag, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, int32, int32) []client.Project); ok {
		r0 = rf(ctx, tag, limit, offset)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, int32, int32) error); ok {
		r1 = rf(ctx, tag, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_GetProjectsByTag_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProjectsByTag'
type MockClient_GetProjectsByTag_Call struct {
	*mock.Call
}

// GetProjectsByTag is a helper method to define mock.On call
//   - ctx context.Context
//   - tag string
//   - limit int32
//   - offset int32
func (_e *MockClient_Expecter) GetProjectsByTag(ctx interface{}, tag interface{}, limit interface{}, offset interface{}) *MockClient_GetProjectsByTag_Call {
	return &MockClient_GetProjectsByTag_Call{Call: _e.mock.On("GetProjectsByTag", ctx, tag, limit, offset)}
}

func (_c *MockClient_GetProjectsByTag_Call) Run(run func(ctx context.Context, tag string, limit int32, offset int32)) *MockClient_GetProjectsByTag_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(int32), args[3].(int32))
	})
	return _c
}

func (_c *MockClient_GetProjectsByTag_Call) Return(_a0 []client.Project, _a1 error) *MockClient_GetProjectsByTag_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_GetProjectsByTag_Call) RunAndReturn(run func(context.Context, string, int32, int32) ([]client.Project, error)) *MockClient_GetProjectsByTag_Call {
	_c.Call.Return(run)
	return _c
}

// TriggerAnalysis provides a mock function with given fields: ctx, uuid
func (_m *MockClient) TriggerAnalysis(ctx context.Context, uuid string) error {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for TriggerAnalysis")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockClient_TriggerAnalysis_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'TriggerAnalysis'
type MockClient_TriggerAnalysis_Call struct {
	*mock.Call
}

// TriggerAnalysis is a helper method to define mock.On call
//   - ctx context.Context
//   - uuid string
func (_e *MockClient_Expecter) TriggerAnalysis(ctx interface{}, uuid interface{}) *MockClient_TriggerAnalysis_Call {
	return &MockClient_TriggerAnalysis_Call{Call: _e.mock.On("TriggerAnalysis", ctx, uuid)}
}

func (_c *MockClient_TriggerAnalysis_Call) Run(run func(ctx context.Context, uuid string)) *MockClient_TriggerAnalysis_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockClient_TriggerAnalysis_Call) Return(_a0 error) *MockClient_TriggerAnalysis_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockClient_TriggerAnalysis_Call) RunAndReturn(run func(context.Context, string) error) *MockClient_TriggerAnalysis_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateFinding provides a mock function with given fields: ctx, suppressedBy, reason, projectId, componentId, vulnerabilityId, state, suppressed
func (_m *MockClient) UpdateFinding(ctx context.Context, suppressedBy string, reason string, projectId string, componentId string, vulnerabilityId string, state string, suppressed bool) error {
	ret := _m.Called(ctx, suppressedBy, reason, projectId, componentId, vulnerabilityId, state, suppressed)

	if len(ret) == 0 {
		panic("no return value specified for UpdateFinding")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, string, string, string, bool) error); ok {
		r0 = rf(ctx, suppressedBy, reason, projectId, componentId, vulnerabilityId, state, suppressed)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockClient_UpdateFinding_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateFinding'
type MockClient_UpdateFinding_Call struct {
	*mock.Call
}

// UpdateFinding is a helper method to define mock.On call
//   - ctx context.Context
//   - suppressedBy string
//   - reason string
//   - projectId string
//   - componentId string
//   - vulnerabilityId string
//   - state string
//   - suppressed bool
func (_e *MockClient_Expecter) UpdateFinding(ctx interface{}, suppressedBy interface{}, reason interface{}, projectId interface{}, componentId interface{}, vulnerabilityId interface{}, state interface{}, suppressed interface{}) *MockClient_UpdateFinding_Call {
	return &MockClient_UpdateFinding_Call{Call: _e.mock.On("UpdateFinding", ctx, suppressedBy, reason, projectId, componentId, vulnerabilityId, state, suppressed)}
}

func (_c *MockClient_UpdateFinding_Call) Run(run func(ctx context.Context, suppressedBy string, reason string, projectId string, componentId string, vulnerabilityId string, state string, suppressed bool)) *MockClient_UpdateFinding_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string), args[4].(string), args[5].(string), args[6].(string), args[7].(bool))
	})
	return _c
}

func (_c *MockClient_UpdateFinding_Call) Return(_a0 error) *MockClient_UpdateFinding_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockClient_UpdateFinding_Call) RunAndReturn(run func(context.Context, string, string, string, string, string, string, bool) error) *MockClient_UpdateFinding_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateProject provides a mock function with given fields: ctx, project
func (_m *MockClient) UpdateProject(ctx context.Context, project *client.Project) (*client.Project, error) {
	ret := _m.Called(ctx, project)

	if len(ret) == 0 {
		panic("no return value specified for UpdateProject")
	}

	var r0 *client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *client.Project) (*client.Project, error)); ok {
		return rf(ctx, project)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *client.Project) *client.Project); ok {
		r0 = rf(ctx, project)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *client.Project) error); ok {
		r1 = rf(ctx, project)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_UpdateProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateProject'
type MockClient_UpdateProject_Call struct {
	*mock.Call
}

// UpdateProject is a helper method to define mock.On call
//   - ctx context.Context
//   - project *client.Project
func (_e *MockClient_Expecter) UpdateProject(ctx interface{}, project interface{}) *MockClient_UpdateProject_Call {
	return &MockClient_UpdateProject_Call{Call: _e.mock.On("UpdateProject", ctx, project)}
}

func (_c *MockClient_UpdateProject_Call) Run(run func(ctx context.Context, project *client.Project)) *MockClient_UpdateProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*client.Project))
	})
	return _c
}

func (_c *MockClient_UpdateProject_Call) Return(_a0 *client.Project, _a1 error) *MockClient_UpdateProject_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_UpdateProject_Call) RunAndReturn(run func(context.Context, *client.Project) (*client.Project, error)) *MockClient_UpdateProject_Call {
	_c.Call.Return(run)
	return _c
}

// UploadSbom provides a mock function with given fields: ctx, projectId, sbom
func (_m *MockClient) UploadSbom(ctx context.Context, projectId string, sbom *in_toto.CycloneDXStatement) error {
	ret := _m.Called(ctx, projectId, sbom)

	if len(ret) == 0 {
		panic("no return value specified for UploadSbom")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *in_toto.CycloneDXStatement) error); ok {
		r0 = rf(ctx, projectId, sbom)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockClient_UploadSbom_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UploadSbom'
type MockClient_UploadSbom_Call struct {
	*mock.Call
}

// UploadSbom is a helper method to define mock.On call
//   - ctx context.Context
//   - projectId string
//   - sbom *in_toto.CycloneDXStatement
func (_e *MockClient_Expecter) UploadSbom(ctx interface{}, projectId interface{}, sbom interface{}) *MockClient_UploadSbom_Call {
	return &MockClient_UploadSbom_Call{Call: _e.mock.On("UploadSbom", ctx, projectId, sbom)}
}

func (_c *MockClient_UploadSbom_Call) Run(run func(ctx context.Context, projectId string, sbom *in_toto.CycloneDXStatement)) *MockClient_UploadSbom_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(*in_toto.CycloneDXStatement))
	})
	return _c
}

func (_c *MockClient_UploadSbom_Call) Return(_a0 error) *MockClient_UploadSbom_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockClient_UploadSbom_Call) RunAndReturn(run func(context.Context, string, *in_toto.CycloneDXStatement) error) *MockClient_UploadSbom_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockClient creates a new instance of MockClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockClient(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockClient {
	mock := &MockClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
