package gtoken

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/container/gset"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"testing"
)

func TestCheckAuthRequired(t *testing.T) {
	t.Log("test: check if auth required")

	publicPaths := []string{
		"/login",       // 1. Resource: Common case
		"POST:/logout", // 2. Resource: Restful format
		"/register/",   // 3. Directory
		"/test/*",      // 4. Prefix match
	}

	// test protected resource, should return true
	if !CheckAuthRequired(publicPaths, "/user", "get") {
		t.Error("error:", "/user protected resource is not detected")
	}
	// test public resource, should return false
	if CheckAuthRequired(publicPaths, "/login", "post") {
		t.Error("error:", "/login excluded resource is not detected")
	}

	// test public resource(restful format), should return false
	if CheckAuthRequired(publicPaths, "/logout", "post") {
		t.Error("error:", "post:/logout protected resource(restful format) is not detected")
	}
	// test protected resource(restful format), should return true
	if !CheckAuthRequired(publicPaths, "/logout", "delete") {
		t.Error("error:", "delete:/logout protected resource(restful format) is not detected")
	}

	// test protected directory, should return true
	if !CheckAuthRequired(publicPaths, "/system/", "get") {
		t.Error("error:", "/system/ protected directory is not detected")
	}
	// test public directory, should return true
	if CheckAuthRequired(publicPaths, "/register/", "post") {
		t.Error("error:", "/register/ public directory is not detected")
	}

	// test public prefix match, should return false
	if CheckAuthRequired(publicPaths, "/test/12aA3", "put") {
		t.Error("error:", "/test/12aA3 public prefix match is not detected")
	}
	// test public prefix match, should return false
	if CheckAuthRequired(publicPaths, "/test/", "get") {
		t.Error("error:", "/test/ public prefix match is not detected")
	}
	// test protected prefix match, should return true
	if !CheckAuthRequired(publicPaths, "/test", "delete") {
		t.Error("error:", "/test protected prefix match is not detected")
	}
}

func TestGetNanoID(t *testing.T) {
	t.Log("test: get nano id")
	idSet := gset.NewStrSet()
	for range 100 {
		id := getNanoID(DefaultTokenIDLength)
		if len(id) != DefaultTokenIDLength {
			t.Error("error:", "nano id length error, come to the fallback")
		}
		if idSet.Contains(id) {
			t.Error("error:", "nano id collision")
		}
		idSet.Add(id)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	t.Log("test: encrypt and decrypt")
	t.Log("1. encrypt token")
	secretKey := []byte(DefaultSecretKey)
	tokenId := getNanoID(DefaultTokenIDLength)
	jwtToken, err := encryptJWT(secretKey, tokenId)
	if err != nil {
		t.Error("encrypt jwt error:", err)
	}
	t.Log("2. decrypt token")
	parsedTokenId, err := decryptJWT(secretKey, jwtToken)
	if err != nil {
		t.Error("decrypt jwt error:", err)
	}
	if parsedTokenId != tokenId {
		t.Error("the parsed token id does not match the given one")
	}
}

func TestParseRequestToken(t *testing.T) {
	t.Log("test: parse request token")
	// new test token
	secretKey := []byte(DefaultSecretKey)
	tokenId := getNanoID(DefaultTokenIDLength)
	jwtToken, err := encryptJWT(secretKey, tokenId)
	if err != nil {
		t.Error("encrypt jwt error:", err)
	}
	testBearerToken := fmt.Sprintf("%s%s", PrefixBearer, jwtToken)
	testTokenInHeaderUrl := "/test1"
	testTokenInParams := fmt.Sprintf("/test2?token=%s", jwtToken)
	testTokenInBody := "/test3"

	s := g.Server()
	s.SetPort(8081)
	hostURL := "http://127.0.0.1:8081"
	s.BindHandler(testTokenInHeaderUrl, func(r *ghttp.Request) {
		parsedToken := ParseRequestToken(r)
		if parsedToken != jwtToken {
			t.Error("parse token from header fail")
		}
		r.Response.WriteExit("ok")
	})
	s.BindHandler(testTokenInParams, func(r *ghttp.Request) {
		parsedToken := ParseRequestToken(r)
		if parsedToken != jwtToken {
			t.Error("parse token from header fail")
		}
		r.Response.WriteExit("ok")
	})
	s.BindHandler(testTokenInBody, func(r *ghttp.Request) {
		parsedToken := ParseRequestToken(r)
		if parsedToken != jwtToken {
			t.Error("parse token from header fail")
		}
		r.Response.WriteExit("ok")
	})
	err = s.Start()
	if err != nil {
		panic(err)
	}

	ctx := context.TODO()
	clientWithHeader := g.Client()
	t.Log("1. parse token from header")
	clientWithHeader.SetHeader("Authorization", testBearerToken)
	_, err = clientWithHeader.Get(ctx, hostURL+testTokenInHeaderUrl)
	if err != nil {
		t.Error("test token in header, request error:", err)
	}
	clientWithoutHeader := g.Client()
	t.Log("2. parse token from params")
	_, err = clientWithoutHeader.Get(ctx, hostURL+testTokenInParams)
	if err != nil {
		t.Error("test token in params, request error:", err)
	}
	t.Log("3. parse token from body")
	_, err = clientWithHeader.Post(ctx, hostURL+testTokenInBody, g.Map{"token": testBearerToken})
	if err != nil {
		t.Error("test token in body, request error:", err)
	}

	err = s.Shutdown()
	if err != nil {
		t.Error("shutdown server error:", err)
	}
}
