package cmd

import (
	"context"
	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcmd"
	"github.com/mayugene/gtoken/example/internal/controller"
	"github.com/mayugene/gtoken/gtoken"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	gToken *gtoken.GToken
	once   sync.Once
)

func UseGToken() *gtoken.GToken {
	once.Do(func() {
		ctx := context.TODO()
		// err can be omitted while getting configs
		cacheMode, _ := g.Cfg().Get(ctx, "auth.cacheMode")
		singleSession, _ := g.Cfg().Get(ctx, "auth.singleSession")
		publicPaths, _ := g.Cfg().Get(ctx, "auth.publicPaths")
		autoRefreshToken, _ := g.Cfg().Get(ctx, "auth.autoRefreshToken")
		expireIn, _ := g.Cfg().Get(ctx, "auth.expireIn")

		gToken = &gtoken.GToken{
			CacheMode:        cacheMode.Uint8(),
			PublicPaths:      strings.Split(publicPaths.String(), ","),
			SingleSession:    singleSession.Bool(),
			AutoRefreshToken: autoRefreshToken.Bool(),
			ExpireIn:         time.Duration(expireIn.Int64()) * time.Second,
		}
	})
	return gToken
}

func SetGToken(ctx context.Context, gt *gtoken.GToken) {
	gToken = gt
	gToken.Init(ctx)
}

var (
	Main = gcmd.Command{
		Name:  "main",
		Usage: "main",
		Brief: "start http server",
		Func: func(ctx context.Context, parser *gcmd.Parser) (err error) {
			s := g.Server()
			SystemInit(s, ctx)
			s.Run()
			return nil
		},
	}
)

func SystemInit(s *ghttp.Server, ctx context.Context) {
	gToken = UseGToken()

	// non-auth apis
	s.Group("/", func(group *ghttp.RouterGroup) {
		group.Middleware(MiddlewareCORS)
		group.Middleware(MiddlewareHandlerResponse)

		group.Bind(controller.Auth)

		group.ALL("/hello", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.DefaultResponse{Msg: "hello"})
		})
	})

	s.Group("/", func(group *ghttp.RouterGroup) {
		group.Middleware(MiddlewareCORS)
		group.Middleware(MiddlewareHandlerResponse)

		err := gToken.UseMiddleware(ctx, group)
		if err != nil {
			panic(err)
		}

		group.GET("/user", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.DefaultResponse{Msg: "get user success"})
		})
		group.POST("/user/data", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.DefaultResponse{Data: g.Map{"id": 33, "name": "abc"}})
		})
		group.ALL("/user/public", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.DefaultResponse{Msg: "public"})
		})
	})
}

func MiddlewareCORS(r *ghttp.Request) {
	r.Response.CORSDefault()
	r.Middleware.Next()
}

// MiddlewareHandlerResponse only modifies the response format of ghttp.MiddlewareHandlerResponse
func MiddlewareHandlerResponse(r *ghttp.Request) {
	r.Middleware.Next()

	// There's custom buffer content, it then exits current handler.
	if r.Response.BufferLength() > 0 || r.Response.Writer.BytesWritten() > 0 {
		return
	}

	var (
		msg  string
		err  = r.GetError()
		res  = r.GetHandlerResponse()
		code = gerror.Code(err)
	)
	if err != nil {
		if code == gcode.CodeNil {
			code = gcode.CodeInternalError
		}
		msg = err.Error()
	} else {
		if r.Response.Status > 0 && r.Response.Status != http.StatusOK {
			switch r.Response.Status {
			case http.StatusNotFound:
				code = gcode.CodeNotFound
			case http.StatusForbidden:
				code = gcode.CodeNotAuthorized
			default:
				code = gcode.CodeUnknown
			}
			// It creates an error as it can be retrieved by other middlewares.
			err = gerror.NewCode(code, msg)
			r.SetError(err)
		} else {
			code = gcode.CodeOK
		}
		msg = code.Message()
	}

	r.Response.WriteJson(gtoken.DefaultResponse{
		Code: code.Code(),
		Msg:  msg,
		Data: res,
	})
}
