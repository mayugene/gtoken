package test

import (
	"context"
	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcfg"
	"github.com/mayugene/gtoken/example/internal/cmd"
	_ "github.com/mayugene/gtoken/example/internal/logic"
	"github.com/mayugene/gtoken/gtoken"
	"os"
	"testing"
	"time"
)

var server *ghttp.Server

func setup() {
	ctx := context.Background()
	g.Log().Info(ctx, "########service start...")

	// ensure use the correct config file
	if fileConfig, ok := g.Cfg().GetAdapter().(*gcfg.AdapterFile); ok {
		err := fileConfig.SetPath("../config")
		if err != nil {
			return
		}
	}
	server = g.Server()
	cmd.SystemInit(server, ctx)

	g.Log().Info(ctx, "########service down.")
	err := server.Start()
	if err != nil {
		panic(err)
	}
}

func teardown() {
	err := server.Shutdown()
	if err != nil {
		return
	}
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func TestHello(t *testing.T) {
	// hello is not under the control of gtoken
	t.Log("test: visit hello with no auth")
	res, err := Get(t, "", ApiHello, "username=admin")
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code != gtoken.DefaultCodeOK {
		t.Error("code should be 0:", res)
	}
}

func TestLoginSuccess(t *testing.T) {
	t.Log("test: login to get token")
	testToken, err := GetToken(t)
	if err != nil || testToken == "" {
		t.Error("login test failed")
	}
	t.Log("login test passed")
}

func TestLoginFail(t *testing.T) {
	t.Log("test: login fail with missing parameters")
	res, err := Post(t, "", ApiLogin, g.Map{"username": "", "password": ""})
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code != gcode.CodeValidationFailed.Code() {
		t.Error("error:", res)
	}

	t.Log("test: login fail with wrong password")
	res1, err := Post(t, "", ApiLogin, g.Map{"username": "123", "password": "ccc"})
	if err != nil {
		t.Error("error:", err)
	}
	if res1.Code != gcode.CodeInternalError.Code() {
		t.Error("error:", res1)
	}
}

func TestLogout(t *testing.T) {
	t.Log("test: logout")
	testToken, err := GetToken(t)
	if err != nil || testToken == "" {
		t.Error("get token error:", err)
	}
	res, err := Post(t, testToken, ApiLogout)
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code == gtoken.DefaultCodeOK {
		t.Log("logout test passed")
	} else {
		t.Error("error:", res)
	}
}

func TestUser(t *testing.T) {
	t.Log("1. not login and get user")
	res, err := Get(t, "", ApiUser)
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code != gtoken.DefaultCodeUnauthorized {
		t.Errorf("code should be %d, but: %v", gtoken.DefaultCodeUnauthorized, res)
	}
	// get token
	testToken, err := GetToken(t)
	if err != nil || testToken == "" {
		t.Error("get token error:", err)
	}

	// test get user
	t.Log("2. execute login and get user")
	res, err = Get(t, testToken, ApiUser)
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code == gtoken.DefaultCodeOK {
		t.Log("get user test passed")
	} else {
		t.Error("error:", res)
	}

	// test post user data
	t.Log("3. execute post user data")
	res, err = Post(t, testToken, ApiUserData)
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code == gtoken.DefaultCodeOK {
		t.Log("post user data test passed")
	} else {
		t.Error("error:", res)
	}

	// test logout
	t.Log("4. execute logout")
	res, err = Post(t, testToken, ApiLogout)
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code == gtoken.DefaultCodeOK {
		t.Log(res)
	} else {
		t.Error("error:", res)
	}

	// test get user
	t.Log("5. get user info")
	res, err = Get(t, testToken, ApiUser)
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code == gtoken.DefaultCodeUnauthorized {
		t.Log("it is true that we can't get user after logout")
	} else {
		t.Error("error:", res)
	}
}

func TestPublicPaths(t *testing.T) {
	// public paths are non-auth
	// here we test a scenario: post is public but get is protected
	t.Log("test public path: post:/user/public")
	res, err := Post(t, "", ApiUserPublic)
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code != gtoken.DefaultCodeOK {
		t.Error("error:", res)
	}

	t.Log("test protected path: get:/user/public")
	res, err = Get(t, "", ApiUserPublic)
	if err != nil {
		t.Error("error:", err)
	}
	if res.Code != gtoken.DefaultCodeUnauthorized {
		t.Error("error:", res)
	}
}

func TestSessions(t *testing.T) {
	t.Run("multiple-sessions", func(t *testing.T) {
		t.Log("test: multiple sessions")
		executeTestSession(t, false) // read from config.yaml, singleSession is false by default
	})
	t.Run("single-session", func(t *testing.T) {
		t.Log("test: single sessions")
		gt := cmd.UseGToken()
		gt.SingleSession = true
		cmd.SetGToken(context.TODO(), gt)
		executeTestSession(t, true)
	})
}

func executeTestSession(t *testing.T, singleSession bool) {
	token1, err := GetToken(t)
	if err != nil || token1 == "" {
		t.Error("get token error:", err)
	}
	t.Log("token1:" + token1)
	token2, err := GetToken(t)
	if err != nil || token2 == "" {
		t.Error("get token error:", err)
	}
	t.Log("token2:" + token2)

	if singleSession {
		// under single session, old token (token1) will be removed
		// if we use token 1 to get user, it should return 401
		res, err1 := Get(t, token1, ApiUser)
		if err1 != nil {
			t.Error("error:", err1)
		}
		if res.Code != gtoken.DefaultCodeUnauthorized {
			t.Errorf("single session test failed, because res code should be %d", gtoken.DefaultCodeUnauthorized)
		}
	} else {
		// under multiple sessions, old token (token1) will not be removed
		// if we use token 1 to get user, it should return 0
		res, err1 := Get(t, token1, ApiUser)
		if err1 != nil {
			t.Error("error:", err1)
		}
		if res.Code != gtoken.DefaultCodeOK {
			t.Errorf("multiple sessions test failed, because res code should be %d", gtoken.DefaultCodeOK)
		}
	}
}

func TestTokenRefresh(t *testing.T) {
	t.Run("NoAutoRefresh", func(t *testing.T) {
		t.Log("autoRefresh=false, login and get first token")
		ctx := context.TODO()
		gt := cmd.UseGToken()
		gt.AutoRefreshToken = false
		gt.ExpireIn = 2 * time.Second
		cmd.SetGToken(ctx, gt)
		token1, err := GetToken(t)
		if err != nil || token1 == "" {
			t.Error("get token error:", err)
		}
		t.Log("start to wait 3 seconds")
		time.Sleep(3 * time.Second)
		t.Log("login again to check if the token has changed")
		token2, err := GetToken(t)
		if err != nil || token2 == "" {
			t.Error("get token error:", err)
		}
		if token1 == token2 {
			t.Error("token1 and token2 are the same: ", token1)
		} else {
			t.Log("it is ok that token1 expires and thus token2 != token1")
		}
	})
	t.Run("AutoRefresh", func(t *testing.T) {
		t.Log("autoRefresh=true, login and get token")
		gt := cmd.UseGToken()
		gt.AutoRefreshToken = true
		gt.ExpireIn = 2 * time.Second
		cmd.SetGToken(context.TODO(), gt)
		token, err := GetToken(t)
		if err != nil || token == "" {
			t.Error("get token error:", err)
		}
		for range 3 {
			// use get user to test if token is still valid
			t.Log("wait 1 second and try to get user")
			time.Sleep(1 * time.Second)
			res, err1 := Get(t, token, ApiUser)
			if err1 != nil {
				t.Error("error: ", err1)
			}
			if res.Code == 0 {
				t.Log("token is still valid")
			} else if res.Code == gtoken.DefaultCodeUnauthorized {
				t.Error("token is invalid")
			} else {
				t.Error("error:", res)
			}
		}
		t.Log("wait 3 second and try to get user")
		time.Sleep(3 * time.Second)
		res, err := Get(t, token, ApiUser)
		if err != nil {
			t.Error("error:", err)
		}
		if res.Code == gtoken.DefaultCodeUnauthorized {
			t.Log("It's right to report 401 here. Because if we don't continuously use the token, it should expire automatically")
		} else if res.Code == 0 {
			t.Error("token should not be valid in this scenario")
		} else {
			t.Error("error:", res)
		}
	})
}
