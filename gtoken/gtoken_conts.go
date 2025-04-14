package gtoken

import (
	"time"
)

const (
	CacheModeCache   = 0
	CacheModeRedis   = 1
	CacheModeFile    = 2
	CacheModeFileDat = "gtoken.dat"

	DefaultExpireIn      = 7 * 24 * time.Hour
	DefaultSecretKey     = "g1t@o3K!e7n"
	DefaultTokenIDLength = 12

	TokenKeyInRequest = "token" // ok for: router, query, body, form, custom

	DefaultLogPrefix = "[GToken]"

	DefaultPrefixToken = "jwt:"
	DefaultPrefixUser  = "user:"

	PrefixBearer = "Bearer "

	DefaultCodeOK           = 0
	DefaultCodeUnauthorized = 401
)

const (
	errorReqMethod     = "request method is error! "
	errorTokenEmpty    = "token is empty"
	errorTokenEncrypt  = "token encrypt error"
	errorTokenDecode   = "token decode error"
	errorSetCache      = "set cache error"
	errorGetCache      = "get cache error"
	errorDeleteCache   = "delete cache error"
	errorDecodeCache   = "decode cache error"
	errorEncodeJson    = "encode json error"
	errorUseCache      = "cache error"
	errorInvalidMode   = "invalid mode"
	errorWriteFile     = "write file error"
	errorTokenNotFound = "token not found"
	errorUnauthorized  = "unauthorized"
	errorUseRedis      = "use redis error"
)
