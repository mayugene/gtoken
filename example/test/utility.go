package test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/mayugene/gtoken/example/api/auth"
	"github.com/mayugene/gtoken/gtoken"
)

const (
	username = "admin"
	password = "123456"
)

var (
	ApiHello      string
	ApiLogin      string
	ApiRefresh    string
	ApiLogout     string
	ApiUser       string
	ApiUserData   string
	ApiUserPublic string
)

func setBaseURL(baseURL string) {
	ApiHello = baseURL + "/hello"
	ApiLogin = baseURL + "/login"
	ApiRefresh = baseURL + "/refresh"
	ApiLogout = baseURL + "/logout"
	ApiUser = baseURL + "/user"
	ApiUserData = baseURL + "/user/data"
	ApiUserPublic = baseURL + "/user/public"
}

// Post contains the logic of login
func Post(t *testing.T, token string, urlPath string, data ...interface{}) (*gtoken.DefaultResponse, error) {
	client := g.Client()
	if token != "" {
		client.SetHeader("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	content := client.RequestContent(context.TODO(), http.MethodPost, urlPath, data...) // this is simple but will omit the http code
	res := gtoken.DefaultResponse{}
	err := gjson.DecodeTo(content, &res)
	if err != nil {
		t.Error("error:", err)
		return nil, err
	}
	return &res, nil
}

// Get contains the logic of login
func Get(t *testing.T, token string, urlPath string, data ...interface{}) (*gtoken.DefaultResponse, error) {
	client := g.Client()
	if token != "" {
		client.SetHeader("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	content := client.RequestContent(context.TODO(), http.MethodGet, urlPath, data...) // this is simple but will omit the http code
	res := gtoken.DefaultResponse{}
	err := gjson.DecodeTo(content, &res)
	if err != nil {
		t.Error("error:", err)
		return nil, err
	}
	return &res, nil
}

// GetToken performs login and get token from response
func GetToken(t *testing.T) (newToken string, err error) {
	loginRes, err := GetTokenPair(t)
	if err != nil {
		return "", err
	}
	return loginRes.Token, nil
}

func GetTokenPair(t *testing.T) (*auth.LoginOutput, error) {
	// GoFrame can parse params from both request body and params, but for a common case, we put them in the request body
	res, err := Post(t, "", ApiLogin, g.Map{"username": username, "password": password})
	if err != nil {
		return nil, err
	}
	if res.Code != gtoken.DefaultCodeOK {
		return nil, fmt.Errorf("login res code is not 0, %v", res)
	}
	var loginRes auth.LoginOutput
	err = gconv.Struct(res.Data, &loginRes)
	if err != nil {
		return nil, err
	}
	return &loginRes, nil
}
