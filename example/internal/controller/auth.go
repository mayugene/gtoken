package controller

import (
	"context"

	"github.com/mayugene/gtoken/example/api/auth"
	"github.com/mayugene/gtoken/example/internal/service"
)

type cAuth struct{}

var Auth = cAuth{}

func (c *cAuth) Login(ctx context.Context, req *auth.LoginReq) (res *auth.LoginRes, err error) {
	return service.Auth().Login(ctx, req.LoginInput)
}

func (c *cAuth) Logout(ctx context.Context, req *auth.LogoutReq) (res *auth.EmptyRes, err error) {
	_, err = service.Auth().Logout(ctx)
	return
}
