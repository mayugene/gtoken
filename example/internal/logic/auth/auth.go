package auth

import (
	"context"
	"errors"
	"time"

	"github.com/gogf/gf/v2/crypto/gmd5"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/mayugene/gtoken/example/api/auth"
	"github.com/mayugene/gtoken/example/internal/cmd"
	"github.com/mayugene/gtoken/example/internal/service"
	"github.com/mayugene/gtoken/gtoken"
)

type sAuth struct{}

func init() {
	service.RegisterAuth(&sAuth{})
}

func (s *sAuth) Login(ctx context.Context, req auth.LoginInput) (res *auth.LoginOutput, err error) {
	if req.Username != "admin" {
		return nil, errors.New("user not found")
	}

	// simply encrypt password using md5
	if gmd5.MustEncrypt(req.Password) != gmd5.MustEncrypt("123456") {
		return nil, errors.New("wrong password")
	}

	userId := ""
	if req.Username == "admin" {
		userId = "99"
	}

	pair, err := cmd.UseGToken().NewTokenPair(ctx, userId, g.Map{"id": 33, "username": req.Username, "nickname": "john"})
	if err != nil {
		return nil, err
	}

	return &auth.LoginOutput{
		TokenType:        "Bearer",
		Token:            pair.AccessToken,
		ExpireIn:         int64(cmd.UseGToken().ExpireIn.Seconds()),
		ExpiresAt:        pair.AccessTokenInfo.ExpireAt.Time.Format(time.RFC3339),
		RefreshToken:     pair.RefreshToken,
		RefreshExpiresAt: pair.RefreshExpiresAt.Time.Format(time.RFC3339),
		Refreshable:      true,
		Username:         req.Username,
	}, nil
}

func (s *sAuth) Refresh(ctx context.Context, req auth.RefreshInput) (*auth.RefreshOutput, error) {
	pair, err := cmd.UseGToken().RefreshTokenPair(ctx, req.RefreshToken, nil)
	if err != nil {
		return nil, gtoken.ErrRefreshTokenRejected
	}
	return &auth.RefreshOutput{
		TokenType:   "Bearer",
		Token:       pair.AccessToken,
		ExpireIn:    int64(cmd.UseGToken().ExpireIn.Seconds()),
		ExpiresAt:   pair.AccessTokenInfo.ExpireAt.Time.Format(time.RFC3339),
		Refreshable: false,
	}, nil
}

func (s *sAuth) Logout(ctx context.Context, req auth.LogoutInput) (bool, error) {
	token := gtoken.ParseRequestToken(g.RequestFromCtx(ctx))
	return true, cmd.UseGToken().RevokeTokenFamily(ctx, token, req.RefreshToken)
}
