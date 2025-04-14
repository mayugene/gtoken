package gtoken

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"net/http"
	"time"
)

type GToken struct {
	CacheMode        uint8                                       // 0 cache (default) 1 redis 2 file
	ExpireIn         time.Duration                               // how long a token will be invalid
	SingleSession    bool                                        // if true, only one token can be kept, so the old one will be deleted
	AutoRefreshToken bool                                        // whether refresh a token automatically. It is a big risk to use "true" in production
	SecretKey        []byte                                      // jwt secret key, why use []byte: https://golang-jwt.github.io/jwt/usage/signing_methods/#frequently-asked-questions
	TokenIDLength    uint8                                       // length of NanoID, default 12
	PublicPaths      []string                                    // non-auth paths. Support restful formats like "POST:/login"
	DoBeforeAuth     func(r *ghttp.Request) (ok bool)            // generally, we omit the file requests in this func
	DoAfterAuth      func(r *ghttp.Request, ok bool, data g.Map) // generally, we add info into context in this func
}

type TokenInfo struct {
	UserID    string      `json:"userID"`
	TokenID   string      `json:"tokenID"`
	ExtraData g.Map       `json:"extraData"`
	ExpireAt  *gtime.Time `json:"ExpireAt"`
	RefreshAt *gtime.Time `json:"RefreshAt"`
}

type DefaultResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

// NewToken returns a new token
func (m *GToken) NewToken(ctx context.Context, userID string, extraData g.Map) (token string, tokenInfo *TokenInfo, err error) {
	// if SingleSession is false, a user can create tokens without limitation.
	// else, only one token could be kept. (The new token will replace the old one)
	if userID == "" {
		return "", nil, fmt.Errorf("a valid userId is required")
	}

	if m.SingleSession {
		// delete the old one
		ok, err1 := m.removeUserCache(ctx, userID)
		if err1 != nil {
			return "", nil, err1
		}
		if !ok {
			return "", nil, fmt.Errorf(gcode.CodeInternalError.Message())
		}
	}

	newToken, newTokenID, err := m.encrypt()
	if err != nil {
		return "", nil, err
	}
	tokenInfo = &TokenInfo{
		UserID:    userID,
		TokenID:   newTokenID,
		ExtraData: extraData,
		ExpireAt:  gtime.Now().Add(m.ExpireIn),
		RefreshAt: gtime.Now().Add(m.ExpireIn / 2),
	}

	ok, err := m.setTokenCache(ctx, newToken, tokenInfo)
	if !ok {
		return "", nil, err
	}
	return newToken, tokenInfo, nil
}

// ValidateToken returns token info. If AutoRefreshToken is true, refresh token ttl.
func (m *GToken) ValidateToken(ctx context.Context, token string) (*TokenInfo, error) {
	tokenInfo, err := m.getTokenCache(ctx, token)
	if err != nil {
		return nil, err
	}

	// handle auto refresh token
	if m.AutoRefreshToken && gtime.Now().Sub(tokenInfo.RefreshAt) > 0 {
		tokenInfo.ExpireAt = gtime.Now().Add(m.ExpireIn)
		tokenInfo.RefreshAt = gtime.Now().Add(m.ExpireIn / 2)
		if ok, err1 := m.refreshTokenCache(ctx, token, tokenInfo); ok {
			return tokenInfo, nil
		} else {
			return nil, err1
		}
	}

	return tokenInfo, nil
}

// RemoveToken deletes Token
func (m *GToken) RemoveToken(ctx context.Context, token string) (ok bool, err error) {
	return m.removeTokenCache(ctx, token)
}

func (m *GToken) Init(ctx context.Context) bool {
	if m.CacheMode == CacheModeFile {
		initCacheModeFile(ctx)
	}
	if m.ExpireIn == 0 {
		m.ExpireIn = DefaultExpireIn
	}

	if len(m.SecretKey) == 0 {
		m.SecretKey = []byte(DefaultSecretKey)
	}

	if m.TokenIDLength == 0 {
		m.TokenIDLength = DefaultTokenIDLength
	}

	if m.DoBeforeAuth == nil {
		m.DoBeforeAuth = func(r *ghttp.Request) bool {
			return !r.IsFileRequest()
		}
	}
	if m.DoAfterAuth == nil {
		m.DoAfterAuth = func(r *ghttp.Request, ok bool, data g.Map) {
			if ok {
				for k, v := range data {
					r.SetCtxVar(k, v)
				}
				r.Middleware.Next()
			} else {
				var params map[string]interface{}
				if r.Method == http.MethodGet {
					params = r.GetMap()
				} else if r.Method == http.MethodPost {
					params = r.GetMap()
				} else {
					r.Response.Writeln(errorReqMethod)
					return
				}

				g.Log().Debug(
					r.Context(),
					fmt.Sprintf("[AUTH_%s][url:%s][params:%s]", gtime.Now().String(), r.URL.Path, params),
				)
				r.Response.WriteJson(DefaultResponse{
					Code: DefaultCodeUnauthorized,
					Msg:  errorUnauthorized,
					Data: data,
				})
				r.ExitAll()
			}
		}
	}

	return true
}

func (m *GToken) UseMiddleware(ctx context.Context, group *ghttp.RouterGroup) error {
	if !m.Init(ctx) {
		return fmt.Errorf("InitConfig fail")
	}
	group.Middleware(m.authMiddleware)
	return nil
}

// authMiddleware should be used as a group middleware
func (m *GToken) authMiddleware(r *ghttp.Request) {
	// handle excluded paths
	if !CheckAuthRequired(m.PublicPaths, r.URL.Path, r.Method) {
		r.Middleware.Next()
		return
	}

	// handle user defined non-auth conditions
	if !m.DoBeforeAuth(r) {
		r.Middleware.Next()
		return
	}

	// perform auth
	// first get token from request
	token := ParseRequestToken(r)
	var ok bool
	var extraData g.Map
	if token != "" {
		userToken, err := m.ValidateToken(r.Context(), token)
		if err == nil {
			ok = true
			extraData = userToken.ExtraData
		}
	}
	m.DoAfterAuth(r, ok, extraData)
}

// encrypt return a valid token
func (m *GToken) encrypt() (token string, id string, err error) {
	id = getNanoID(m.TokenIDLength)
	token, err = encryptJWT(m.SecretKey, id)
	if err != nil {
		return "", "", fmt.Errorf(errorTokenEncrypt)
	}
	return token, id, nil
}
