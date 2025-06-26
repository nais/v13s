package dependencytrack

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/v13s/internal/sources/dependencytrack/client"
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
