// ================================================================================
// Code generated and maintained by GoFrame CLI tool. DO NOT EDIT.
// You can delete these comments if you wish manually maintain this interface file.
// ================================================================================

package service

import (
	"context"

	"github.com/mayugene/gtoken/example/internal/model"
)

type (
	IAuth interface {
		Login(ctx context.Context, req model.AuthLoginInput) (res *model.AuthLoginOutput, err error)
		Logout(ctx context.Context) (bool, error)
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
