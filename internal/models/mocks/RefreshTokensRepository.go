// Code generated by mockery v2.38.0. DO NOT EDIT.

package mocks

import (
	context "context"

	models "github.com/leokuzmanovic/go-echo-example/internal/models"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/gofrs/uuid"
)

// RefreshTokensRepository is an autogenerated mock type for the RefreshTokensRepository type
type RefreshTokensRepository struct {
	mock.Mock
}

// Create provides a mock function with given fields: ctx, id, refreshToken, userId
func (_m *RefreshTokensRepository) Create(ctx context.Context, id string, refreshToken string, userId uuid.UUID) error {
	ret := _m.Called(ctx, id, refreshToken, userId)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, uuid.UUID) error); ok {
		r0 = rf(ctx, id, refreshToken, userId)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Delete provides a mock function with given fields: ctx, id
func (_m *RefreshTokensRepository) Delete(ctx context.Context, id string) error {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteByUserID provides a mock function with given fields: ctx, userID
func (_m *RefreshTokensRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	ret := _m.Called(ctx, userID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteByUserID")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) error); ok {
		r0 = rf(ctx, userID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Get provides a mock function with given fields: ctx, id
func (_m *RefreshTokensRepository) Get(ctx context.Context, id string) (*models.RefreshTokenData, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for Get")
	}

	var r0 *models.RefreshTokenData
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*models.RefreshTokenData, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *models.RefreshTokenData); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*models.RefreshTokenData)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewRefreshTokensRepository creates a new instance of RefreshTokensRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewRefreshTokensRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *RefreshTokensRepository {
	mock := &RefreshTokensRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}