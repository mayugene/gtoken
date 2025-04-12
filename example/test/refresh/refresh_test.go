package refresh

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
	"time"
)

const (
	baseURL  = "http://127.0.0.1:8081"
	apiLogin = baseURL + "/login"
	apiUser  = baseURL + "/user"
)

var (
	username = "admin"
	password = "123456"
	server   *ghttp.Server
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
		fileConfig.SetFileName("config.refresh.yaml")
	}
	a, _ := g.Cfg().Data(ctx)
	fmt.Println("in refresh setup: ", a)
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

func TestNotAutoRefresh(t *testing.T) {
	t.Log("autoRefresh=false, login and get first token")
	token1 := getToken(t)
	t.Log("start to wait 3 seconds")
	time.Sleep(3 * time.Second)
	t.Log("login again to check if the token has changed")
	token2 := getToken(t)
	if token1 == token2 {
		t.Error("token1 and token2 are the same: ", token1)
	} else {
		t.Log("it is ok that token1 expires and thus token2 != token1")
	}
}

func TestAutoRefresh(t *testing.T) {
	t.Log("autoRefresh=true, login and get token")
	gt := cmd.UseGToken()
	gt.AutoRefreshToken = true
	cmd.SetGToken(context.TODO(), gt)
	token := getToken(t)
	for range 3 {
		// use get user to test if token is still valid
		t.Log("wait 1 second and try to get user")
		time.Sleep(1 * time.Second)
		res := Get(t, token, apiUser)
		if res.Code == 0 {
			t.Log("token is still valid")
		} else if res.Code == 401 {
			t.Error("token is invalid")
		} else {
			t.Error("error:", res)
		}
	}
	t.Log("wait 3 second and try to get user")
	time.Sleep(3 * time.Second)
	res := Get(t, token, apiUser)
	if res.Code == 401 {
		t.Log("It's right to report 401 here. Because if we don't continuously use the token, it should expire automatically")
	} else if res.Code == 0 {
		t.Error("token should not be valid in this scenario")
	} else {
		t.Error("error:", res)
	}
}

// Get contains the logic of login
func Get(t *testing.T, token string, urlPath string, data ...interface{}) gtoken.DefaultResponse {
	client := g.Client()
	client.SetHeader("Authorization", "Bearer "+token)
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
	// GoFrame can parse params from both request body and params, but for a common case, we put them in the request body
	if r, err := g.Client().Post(context.TODO(), apiLogin, g.Map{"username": username, "password": password}); err != nil {
		t.Error("error:", err)
		return ""
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
		token, err := parseTokenFromResData(resp.Data)
		if err != nil {
			t.Error("error:", err)
		}
		return token
	}
}

func parseTokenFromResData(resData interface{}) (string, error) {
	var loginRes model.AuthLoginOutput
	err := gconv.Struct(resData, &loginRes)
	if err != nil {
		return "", err
	}
	return loginRes.Token, nil
}
