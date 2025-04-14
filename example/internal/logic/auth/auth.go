package auth

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/crypto/gmd5"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/mayugene/gtoken/example/internal/cmd"
	"github.com/mayugene/gtoken/example/internal/model"
	"github.com/mayugene/gtoken/example/internal/service"
	"github.com/mayugene/gtoken/gtoken"
)

type sAuth struct{}

func init() {
	service.RegisterAuth(&sAuth{})
}

func (s *sAuth) Login(ctx context.Context, req model.AuthLoginInput) (res *model.AuthLoginOutput, err error) {
	if req.Username != "admin" {
		return nil, fmt.Errorf("user not found")
	}

	// simply encrypt password using md5
	if gmd5.MustEncrypt(req.Password) != gmd5.MustEncrypt("123456") {
		return nil, fmt.Errorf("wrong password")
	}

	userId := ""
	if req.Username == "admin" {
		userId = "99"
	}

	newToken, _, err := cmd.UseGToken().NewToken(ctx, userId, g.Map{"id": 33, "username": req.Username, "nickname": "john"})
	if err != nil {
		return nil, err
	}

	return &model.AuthLoginOutput{
		TokenType: "Bearer",
		Token:     newToken,
		ExpireIn:  int64(cmd.UseGToken().ExpireIn.Seconds()),
		Username:  req.Username,
	}, nil
}

func (s *sAuth) Logout(ctx context.Context) (bool, error) {
	token := gtoken.ParseRequestToken(g.RequestFromCtx(ctx))
	return cmd.UseGToken().RemoveToken(ctx, token)
}
