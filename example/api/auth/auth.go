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

type RefreshReq struct {
	g.Meta `path:"/refresh" method:"post" tags:"auth" summary:"refresh once"`
	RefreshInput
}

type RefreshRes = RefreshOutput

type LogoutReq struct {
	g.Meta `path:"/logout" method:"post" tags:"auth" summary:"logout"`
	LogoutInput
}
