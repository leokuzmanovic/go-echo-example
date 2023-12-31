// Code generated by mockery v2.38.0. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
	null "gopkg.in/guregu/null.v4"
)

// AuthService is an autogenerated mock type for the AuthService type
type AuthService struct {
	mock.Mock
}

// Login provides a mock function with given fields: ctx, username, password
func (_m *AuthService) Login(ctx context.Context, username string, password string) (null.String, null.String, error) {
	ret := _m.Called(ctx, username, password)

	if len(ret) == 0 {
		panic("no return value specified for Login")
	}

	var r0 null.String
	var r1 null.String
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (null.String, null.String, error)); ok {
		return rf(ctx, username, password)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) null.String); ok {
		r0 = rf(ctx, username, password)
	} else {
		r0 = ret.Get(0).(null.String)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) null.String); ok {
		r1 = rf(ctx, username, password)
	} else {
		r1 = ret.Get(1).(null.String)
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string) error); ok {
		r2 = rf(ctx, username, password)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// Logout provides a mock function with given fields: ctx, refreshToken
func (_m *AuthService) Logout(ctx context.Context, refreshToken string) error {
	ret := _m.Called(ctx, refreshToken)

	if len(ret) == 0 {
		panic("no return value specified for Logout")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, refreshToken)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RefreshToken provides a mock function with given fields: ctx, refreshToken
func (_m *AuthService) RefreshToken(ctx context.Context, refreshToken string) (null.String, null.String, error) {
	ret := _m.Called(ctx, refreshToken)

	if len(ret) == 0 {
		panic("no return value specified for RefreshToken")
	}

	var r0 null.String
	var r1 null.String
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (null.String, null.String, error)); ok {
		return rf(ctx, refreshToken)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) null.String); ok {
		r0 = rf(ctx, refreshToken)
	} else {
		r0 = ret.Get(0).(null.String)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) null.String); ok {
		r1 = rf(ctx, refreshToken)
	} else {
		r1 = ret.Get(1).(null.String)
	}

	if rf, ok := ret.Get(2).(func(context.Context, string) error); ok {
		r2 = rf(ctx, refreshToken)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// NewAuthService creates a new instance of AuthService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAuthService(t interface {
	mock.TestingT
	Cleanup(func())
}) *AuthService {
	mock := &AuthService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
