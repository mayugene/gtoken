package controller

import (
	"context"
	"github.com/mayugene/gtoken/example/api"
	"github.com/mayugene/gtoken/example/internal/model"
	"github.com/mayugene/gtoken/example/internal/service"
)

type cAuth struct{}

var Auth = cAuth{}

func (c *cAuth) Login(ctx context.Context, req *api.AuthLoginReq) (res *api.AuthLoginRes, err error) {
	out, err := service.Auth().Login(ctx, model.AuthLoginInput{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		return nil, err
	}
	return (*api.AuthLoginRes)(out), nil
}

func (c *cAuth) Logout(ctx context.Context, req *api.AuthLogoutReq) (res *api.EmptyRes, err error) {
	_, err = service.Auth().Logout(ctx)
	return
}
