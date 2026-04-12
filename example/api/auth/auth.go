package auth

import (
	"github.com/gogf/gf/v2/frame/g"
)

type EmptyRes struct{}

type LoginReq struct {
	g.Meta `path:"/login" method:"post" tags:"auth" summary:"login"`
	LoginInput
}

type LoginRes = LoginOutput

type LogoutReq struct {
	g.Meta `path:"/logout" method:"post" tags:"auth" summary:"logout"`
}
