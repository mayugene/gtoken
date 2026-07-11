package service

import (
	"context"

	"github.com/mayugene/gtoken/example/api/auth"
)

type (
	IAuth interface {
		Login(ctx context.Context, req auth.LoginInput) (res *auth.LoginOutput, err error)
		Refresh(ctx context.Context, req auth.RefreshInput) (res *auth.RefreshOutput, err error)
		Logout(ctx context.Context, req auth.LogoutInput) (bool, error)
	}
)

var (
	localAuth IAuth
)

func Auth() IAuth {
	if localAuth == nil {
		panic("implement not found for interface IAuth, forgot register?")
	}
	return localAuth
}

func RegisterAuth(i IAuth) {
	localAuth = i
}
