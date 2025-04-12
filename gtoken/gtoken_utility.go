package gtoken

import (
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/matoous/go-nanoid/v2"
	"strings"
)

func CheckAuthRequired(publicPaths []string, urlPath string, urlMethod string) bool {
	/*
			Checks whether a path needs to do auth

			publicPaths support common formats like "/login" and restful formats like "POST:/login"

			Supported URL path formats:
			1. Prefix match
				/test/* matches:
					 /test/, /test/abc, /test/123, /test/123/abc
				/test/* not matches:
					/test, /testing
		 	2. Full match
				/test  matches /test
				/test/ matches /test/
	*/
	urlMethod = strings.ToUpper(urlMethod) // ensure to be POST, PUT, etc.

	for _, allowItem := range publicPaths {
		var allowMethod, allowPath string
		allowItemSlice := gstr.Split(allowItem, ":")
		if len(allowItemSlice) == 2 {
			allowMethod = strings.ToUpper(allowItemSlice[0]) // force to be POST, PUT, etc.
			allowPath = allowItemSlice[1]
		} else {
			allowPath = allowItemSlice[0]
		}

		isMethodMatched := allowMethod == "" || allowMethod == urlMethod

		if strings.HasSuffix(allowPath, "/*") {
			// check prefix match
			if strings.HasPrefix(urlPath, allowPath[:len(allowPath)-1]) && isMethodMatched {
				return false
			}
		} else {
			// check full match
			if urlPath == allowPath && isMethodMatched {
				return false
			}
		}
	}
	return true
}

func GetNanoId(length uint8) string {
	// Use 12 bytes nanoid by default
	// If 1000 IDs per hour, ~1 thousand years or 9B IDs needed, in order to have a 1% probability of at least one collision.
	// Refer to: https://zelark.github.io/nano-id-cc/
	id, err := gonanoid.New(int(length))
	if err != nil {
		// use nano ts as a fallback
		return gtime.TimestampNanoStr()
	}
	return id
}
