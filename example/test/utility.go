package test

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/mayugene/gtoken/example/internal/model"
	"github.com/mayugene/gtoken/gtoken"
	"net/http"
	"testing"
)

const (
	username = "admin"
	password = "123456"
)

const baseURL = "http://127.0.0.1:8081"
const (
	ApiHello      = baseURL + "/hello"
	ApiLogin      = baseURL + "/login"
	ApiLogout     = baseURL + "/logout"
	ApiUser       = baseURL + "/user"
	ApiUserData   = baseURL + "/user/data"
	ApiUserPublic = baseURL + "/user/public"
)

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
	// GoFrame can parse params from both request body and params, but for a common case, we put them in the request body
	res, err := Post(t, "", ApiLogin, g.Map{"username": username, "password": password})
	if err != nil {
		return "", err
	}
	if res.Code != gtoken.DefaultCodeOK {
		return "", fmt.Errorf("login res code is not 0, %v", res)
	}
	var loginRes model.AuthLoginOutput
	err = gconv.Struct(res.Data, &loginRes)
	if err != nil {
		return "", err
	}
	return loginRes.Token, nil
}
