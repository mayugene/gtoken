package api

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcfg"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/mayugene/gtoken/example/internal/cmd"
	_ "github.com/mayugene/gtoken/example/internal/logic"
	"github.com/mayugene/gtoken/example/internal/model"
	"github.com/mayugene/gtoken/gtoken"
	"net/http"
	"os"
	"testing"
)

const baseURL = "http://127.0.0.1:8081"
const (
	apiHello      = baseURL + "/hello"
	apiLogin      = baseURL + "/login"
	apiLogout     = baseURL + "/logout"
	apiUser       = baseURL + "/user"
	apiUserData   = baseURL + "/user/data"
	apiUserPublic = baseURL + "/user/public"
)

var (
	currentToken = ""
	username     = "admin"
	password     = "123456"
	server       *ghttp.Server
)

func setup() {
	fmt.Println("start...")
	ctx := context.Background()
	g.Log().Info(ctx, "########service start...")

	// ensure use the correct config file
	if fileConfig, ok := g.Cfg().GetAdapter().(*gcfg.AdapterFile); ok {
		err := fileConfig.SetPath("../../config")
		if err != nil {
			return
		}
	}
	a, _ := g.Cfg().Data(ctx)
	fmt.Println("in api setup: ", a)
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
	fmt.Println("stop.")
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
	if r, err := g.Client().Get(context.TODO(), apiHello, "username="+username); err != nil {
		t.Error("error:", err)
	} else {
		defer r.Close()

		content := string(r.ReadAll())
		t.Log(content)

		var resp gtoken.DefaultResponse
		err = gjson.DecodeTo(content, &resp)
		if err != nil {
			t.Error("error:", err)
		}
		if resp.Code != 0 {
			t.Error("code should be 0:", content)
		}
	}
}

func TestLoginSuccess(t *testing.T) {
	t.Log("test: login to get token")
	if token := getToken(t); token == "" {
		t.Error("login test failed")
	} else {
		t.Log("login test passed")
	}
	currentToken = ""
}

func TestLoginFail(t *testing.T) {
	t.Log("test: login fail with missing parameters")
	if r, err := g.Client().Post(context.TODO(), apiLogin, g.Map{"username": "", "password": ""}); err != nil {
		t.Error("error:", err)
	} else {
		defer r.Close()

		content := string(r.ReadAll())

		var resp gtoken.DefaultResponse
		err = gjson.DecodeTo(content, &resp)
		if err != nil {
			t.Error("error:", err)
		}

		if resp.Code != 51 {
			t.Error("error:", "error code")
		}
	}

	t.Log("test: login fail with wrong password")
	if r, err := g.Client().Post(context.TODO(), apiLogin, g.Map{"username": "123", "password": "ccc"}); err != nil {
		t.Error("error:", err)
	} else {
		defer r.Close()

		content := string(r.ReadAll())

		var resp gtoken.DefaultResponse
		err = gjson.DecodeTo(content, &resp)
		if err != nil {
			t.Error("error:", err)
		}

		if resp.Code != 50 {
			t.Error("error:", "error code")
		}
	}
}

func TestLogout(t *testing.T) {
	t.Log("test: logout")
	res := Post(t, apiLogout)
	if res.Code == 0 {
		t.Log("logout test passed")
	} else {
		t.Error("error:", res)
	}
	currentToken = ""
}

func TestUser(t *testing.T) {
	t.Log("1. not login and get user")
	if r, err := g.Client().Get(context.TODO(), apiUser); err != nil {
		t.Error("error:", err)
	} else {
		defer r.Close()

		content := string(r.ReadAll())
		t.Log(content)

		var resp gtoken.DefaultResponse
		err = gjson.DecodeTo(content, &resp)
		if err != nil {
			t.Error("error:", err)
		}
		if resp.Code != 401 {
			t.Error("code should be 401:", content)
		}
	}

	// test get user
	t.Log("2. execute login and get user")
	res := Get(t, apiUser)
	if res.Code == 0 {
		t.Log("get user test passed")
	} else {
		t.Error("error:", res)
	}

	// test post user data
	t.Log("3. execute post user data")
	res = Post(t, apiUserData)
	if res.Code == 0 {
		t.Log("post user data test passed")
	} else {
		t.Error("error:", res)
	}

	// test logout
	t.Log("4. execute logout")
	res = Post(t, apiLogout)
	if res.Code == 0 {
		t.Log(res)
	} else {
		t.Error("error:", res)
	}

	// test get user
	t.Log("5. get user info")
	res = Get(t, apiUser)
	if res.Code == 401 {
		t.Log("it is true that we can't get user after logout")
	} else {
		t.Error("error:", res)
	}
	currentToken = ""
}

func TestPublicPaths(t *testing.T) {
	// public paths are non-auth
	// here we test a scenario: post is public but get is protected
	t.Log("test public path: post:/user/public")
	if r, err := g.Client().Post(context.TODO(), apiUserPublic); err != nil {
		t.Error("error:", err)
	} else {
		defer r.Close()

		content := string(r.ReadAll())
		t.Log(content)

		var resp gtoken.DefaultResponse
		err = gjson.DecodeTo(content, &resp)
		if err != nil {
			t.Error("error:", err)
		}
		if resp.Code != 0 {
			t.Error("error:", content)
		}
	}

	t.Log("test protected path: get:/user/public")
	if r, err := g.Client().Get(context.TODO(), apiUserPublic); err != nil {
		t.Error("error:", err)
	} else {
		defer r.Close()

		content := string(r.ReadAll())
		t.Log(content)

		var resp gtoken.DefaultResponse
		err = gjson.DecodeTo(content, &resp)
		if err != nil {
			t.Error("error:", err)
		}
		if resp.Code != 401 {
			t.Error("error:", content)
		}
	}
}

func TestMultiLogin(t *testing.T) {
	t.Log(" TestMultiLogin start... ")
	var token1, token2 string
	if r, err := g.Client().Post(context.TODO(), apiLogin, g.Map{"username": username, "password": password}); err != nil {
		t.Error("error:", err)
	} else {
		defer r.Close()

		content := string(r.ReadAll())
		t.Log("token1 content:" + content)

		var resp gtoken.DefaultResponse
		err = gjson.DecodeTo(content, &resp)
		if err != nil {
			t.Error("error:", err)
		}

		if resp.Code != 0 {
			t.Error("error:", "resp fail:"+content)
		}

		token1, err = parseTokenFromResData(resp.Data)
		if err != nil {
			t.Error("error:", err)
		}
	}
	t.Log("token1:" + token1)

	if r, err := g.Client().Post(context.TODO(), apiLogin, g.Map{"username": username, "password": password}); err != nil {
		t.Error("error:", err)
	} else {
		defer r.Close()

		content := string(r.ReadAll())
		t.Log("token2 content:" + content)

		var resp gtoken.DefaultResponse
		err = gjson.DecodeTo(content, &resp)
		if err != nil {
			t.Error("error:", err)
		}

		if resp.Code != 0 {
			t.Error("error:", "resp fail:"+content)
		}

		token2, err = parseTokenFromResData(resp.Data)
		if err != nil {
			t.Error("error:", err)
		}
	}

	t.Log("token2:" + token2)

	gVar, err := g.Cfg().Get(context.TODO(), "auth.multiLogin")
	if err != nil {
		t.Error("error:", err)
	}
	if gVar.Bool() {
		if token1 != token2 {
			t.Error("error:", "token not same ")
		}
	} else {
		if token1 == token2 {
			t.Error("error:", "token same ")
		}
	}
}

// Post contains the logic of login
func Post(t *testing.T, urlPath string, data ...interface{}) gtoken.DefaultResponse {
	client := g.Client()
	client.SetHeader("Authorization", "Bearer "+getToken(t))
	content := client.RequestContent(context.TODO(), http.MethodPost, urlPath, data...) // this is simple but will omit the http code
	var resp gtoken.DefaultResponse
	err := gjson.DecodeTo(content, &resp)
	if err != nil {
		t.Error("error:", err)
	}
	return resp
}

// Get contains the logic of login
func Get(t *testing.T, urlPath string, data ...interface{}) gtoken.DefaultResponse {
	client := g.Client()
	client.SetHeader("Authorization", "Bearer "+getToken(t))
	content := client.RequestContent(context.TODO(), http.MethodGet, urlPath, data...) // this is simple but will omit the http code
	var resp gtoken.DefaultResponse
	err := gjson.DecodeTo(content, &resp)
	if err != nil {
		t.Error("error:", err)
	}
	return resp
}

// getToken performs login and get token from response
func getToken(t *testing.T) string {
	if currentToken != "" {
		return currentToken
	}
	// GoFrame can parse params from both request body and params, but for a common case, we put them in the request body
	if r, err := g.Client().Post(context.TODO(), apiLogin, g.Map{"username": username, "password": password}); err != nil {
		t.Error("error:", err)
	} else {
		defer r.Close()

		content := string(r.ReadAll())

		var resp gtoken.DefaultResponse
		err = gjson.DecodeTo(content, &resp)
		if err != nil {
			t.Error("error:", err)
		}

		if resp.Code != 0 {
			t.Error("error:", "resp fail:"+content)
		}
		currentToken, err = parseTokenFromResData(resp.Data)
		if err != nil {
			t.Error("error:", err)
		}
	}
	return currentToken
}

func parseTokenFromResData(resData interface{}) (string, error) {
	var loginRes model.AuthLoginOutput
	err := gconv.Struct(resData, &loginRes)
	if err != nil {
		return "", err
	}
	return loginRes.Token, nil
}
