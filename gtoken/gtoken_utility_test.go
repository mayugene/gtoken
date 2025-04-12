package gtoken

import (
	"github.com/gogf/gf/v2/container/gset"
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

func TestGetNanoId(t *testing.T) {
	t.Log("test: get nano id")
	idSet := gset.NewStrSet()
	for range 100 {
		id := GetNanoId(DefaultTokenIdLength)
		if len(id) != DefaultTokenIdLength {
			t.Error("error:", "nano id length error, come to the fallback")
		}
		if idSet.Contains(id) {
			t.Error("error:", "nano id collision")
		}
		idSet.Add(id)
	}
}
