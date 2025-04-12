package api

import (
	"github.com/gogf/gf/v2/frame/g"
	"github.com/mayugene/gtoken/example/internal/model"
)

type EmptyRes struct{}

type AuthLoginReq struct {
	g.Meta `path:"/login" method:"post" tags:"auth" summary:"login"`
	model.AuthLoginInput
}

type AuthLoginRes model.AuthLoginOutput

type AuthLogoutReq struct {
	g.Meta `path:"/logout" method:"post" tags:"auth" summary:"logout"`
}
