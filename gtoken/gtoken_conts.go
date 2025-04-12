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
	DefaultEncryptKey    = "g1t@o3K!e7n"
	DefaultTokenIdLength = 12

	TokenKeyInRequest = "token" // ok for: router, query, body, form, custom

	DefaultLogPrefix = "[GToken]"
)

const (
	codeUnauthorized   = 401
	errorUserKeyEmpty  = "userKey is empty"
	errorReqMethod     = "request method is error! "
	errorAuthHeader    = "Authorization : %s get token key fail"
	errorTokenEmpty    = "token is empty"
	errorTokenEncrypt  = "token encrypt error"
	errorTokenDecode   = "token decode error"
	errorSetCache      = "set cache error"
	errorGetCache      = "get cache error"
	errorDeleteCache   = "delete cache error"
	errorDecodeCache   = "decode cache error"
	errorEncodeCache   = "encode cache error"
	errorInvalidMode   = "invalid mode"
	errorWriteFile     = "write file error"
	errorTokenNotFound = "token not found"
	errorUnauthorized  = "unauthorized"
)
