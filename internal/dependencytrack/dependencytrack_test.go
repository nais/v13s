package dependencytrack

import (
	"context"
	"errors"
	"testing"

	"github.com/nais/v13s/internal/dependencytrack/client"
	"github.com/stretchr/testify/assert"
)

func TestGetFindings(t *testing.T) {
	mockClient := new(MockClient)
	ctx := context.Background()
	uuid := "test-uuid"
	var sampleFindings []client.Finding

	mockClient.On("GetFindings", ctx, uuid, "", false).Return(sampleFindings, nil)

	findings, err := mockClient.GetFindings(ctx, uuid, "", false)

	assert.NoError(t, err)
	assert.Equal(t, sampleFindings, findings)
	mockClient.AssertExpectations(t)
}

func TestGetProjectsByTag(t *testing.T) {
	mockClient := new(MockClient)
	ctx := context.Background()
	tag := "test-tag"
	limit := int32(3)
	offset := int32(0)
	projectNames := []string{"Project1", "Project2", "Project3"}
	var sampleProjects []client.Project
	for _, name := range projectNames {
		sampleProjects = append(sampleProjects, client.Project{Name: &name})
	}

	mockClient.On("GetProjectsByTag", ctx, tag, limit, offset).Return(sampleProjects, nil)

	projects, err := mockClient.GetProjectsByTag(ctx, tag, limit, offset)

	assert.NoError(t, err)
	assert.Equal(t, sampleProjects, projects)
	mockClient.AssertExpectations(t)
}

func TestPaginateProjects(t *testing.T) {
	mockClient := new(MockClient)
	ctx := context.Background()
	limit := int32(2)
	offset := int32(0)

	project1 := "Project1"
	project2 := "Project2"

	page1 := []client.Project{{Name: &project1}, {Name: &project2}}
	mockClient.On("GetProjects", ctx, limit, offset).Return(page1, nil)

	projects, err := mockClient.GetProjects(ctx, limit, offset)

	assert.NoError(t, err)
	assert.Len(t, projects, 2)
	assert.Equal(t, project1, *projects[0].Name)
	mockClient.AssertExpectations(t)

	mockClient = new(MockClient)
	mockClient.On("GetProjects", ctx, limit, offset).Return([]client.Project{}, nil)

	projects, err = mockClient.GetProjects(ctx, limit, offset)

	assert.NoError(t, err)
	assert.Len(t, projects, 0)

	mockClient = new(MockClient)
	mockClient.On("GetProjects", ctx, limit, offset).Return(nil, errors.New("API error"))

	projects, err = mockClient.GetProjects(ctx, limit, offset)

	assert.Error(t, err)
	assert.Len(t, projects, 0)
}

func TestGetProjectsByTag_Error(t *testing.T) {
	mockClient := new(MockClient)
	ctx := context.Background()
	tag := "invalid-tag"
	limit := int32(2)
	offset := int32(0)

	expectedErr := errors.New("API error")
	mockClient.On("GetProjectsByTag", ctx, tag, limit, offset).Return(nil, expectedErr)

	projects, err := mockClient.GetProjectsByTag(ctx, tag, limit, offset)

	assert.Error(t, err)
	assert.Nil(t, projects)
	assert.Equal(t, expectedErr, err)
	mockClient.AssertExpectations(t)
}
