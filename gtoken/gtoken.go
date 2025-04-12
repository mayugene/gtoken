package gtoken

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
	"time"
)

type GToken struct {
	CacheMode        uint8                                       // 0 cache (default) 1 redis 2 file
	ExpireIn         time.Duration                               // how long a token will be invalid
	AutoRefreshToken bool                                        // whether refresh a token automatically. It is a big risk to use "true" in production.
	SecretKey        []byte                                      // jwt secret key, why use []byte: https://golang-jwt.github.io/jwt/usage/signing_methods/#frequently-asked-questions
	TokenIdLength    uint8                                       // length of NanoId, default 12
	MultiLogin       bool                                        // To be simple, if true, will return the same token while token is still valid
	PublicPaths      []string                                    // Non-auth paths. Support restful formats like "POST:/login".
	DoBeforeAuth     func(r *ghttp.Request) (ok bool)            // Generally, we omit the file requests in this func
	DoAfterAuth      func(r *ghttp.Request, ok bool, data g.Map) // Generally, we add info into context in this func
}

type UserToken struct {
	ID        string      `json:"id"`
	UserKey   string      `json:"userKey"`
	Token     string      `json:"token"`
	CreateAt  *gtime.Time `json:"createAt"`
	RefreshAt *gtime.Time `json:"refreshAt"`
	ExpireAt  *gtime.Time `json:"expireAt"`
	ExtraData g.Map       `json:"extraData"`
}

type DefaultResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data"`
}

// NewToken returns a new token
func (m *GToken) NewToken(ctx context.Context, userKey string, extraData g.Map) (*UserToken, error) {
	// under multi-login, token will be reused and refreshed automatically
	if m.MultiLogin {
		existedToken, _ := m.getCachedToken(ctx, userKey)
		if existedToken != nil {
			return existedToken, nil
		}
	}

	newToken, err := m.encrypt(userKey)
	if err != nil {
		return nil, err
	}

	newToken.CreateAt = gtime.Now()
	newToken.ExpireAt = newToken.CreateAt.Add(m.ExpireIn)
	newToken.RefreshAt = newToken.CreateAt.Add(m.ExpireIn / 2) // use m.ExpireIn / 2 as refresh interval
	newToken.ExtraData = extraData

	ok, err := m.setCache(ctx, newToken)
	if ok {
		return newToken, nil
	}
	return nil, err
}

// ValidateToken returns a valid token or nil
func (m *GToken) ValidateToken(ctx context.Context, token string) (*UserToken, error) {
	userKey, tokenId, err := m.decrypt(token)
	if err != nil {
		return nil, err
	}

	userToken, err := m.getCachedToken(ctx, userKey)
	if err != nil {
		return nil, err
	}
	// if id does not match, it might be tampered
	if userToken.ID != tokenId {
		return nil, fmt.Errorf(errorTokenNotFound)
	}

	return userToken, nil
}

// RemoveToken deletes Token
func (m *GToken) RemoveToken(ctx context.Context, token string) (ok bool, err error) {
	userKey, _, err := m.decrypt(token)
	if err != nil {
		return false, err
	}

	return m.removeCache(ctx, userKey)
}

// Init 初始化配置信息
func (m *GToken) Init(ctx context.Context) bool {
	if m.CacheMode == CacheModeFile {
		m.initCacheModeFile(ctx)
	}
	if m.ExpireIn == 0 {
		m.ExpireIn = DefaultExpireIn
	}

	if len(m.SecretKey) == 0 {
		m.SecretKey = []byte(DefaultEncryptKey)
	}

	if m.TokenIdLength == 0 {
		m.TokenIdLength = DefaultTokenIdLength
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
					Code: codeUnauthorized,
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
	token := m.ParseRequestToken(r)
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

// ParseRequestToken tries to get token from the following path by priority:
// 1. header.Authorization
// 2. token
func (m *GToken) ParseRequestToken(r *ghttp.Request) string {
	// 1. from header.Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			WriteLog(r.Context(), fmt.Sprintf("%s, %s", errorAuthHeader, authHeader), LogLevelWarning)
			return ""
		} else if parts[1] == "" {
			WriteLog(r.Context(), fmt.Sprintf("%s, %s", errorAuthHeader, authHeader), LogLevelWarning)
			return ""
		}

		return parts[1]
	}
	// 2. from token
	return r.Get(TokenKeyInRequest).String()
}

// getCachedToken gets token by userKey
func (m *GToken) getCachedToken(ctx context.Context, userKey string) (*UserToken, error) {
	userToken, err := m.getCache(ctx, userKey)
	if err != nil {
		return nil, err
	}

	// handle auto refresh token
	if m.AutoRefreshToken && gtime.Now().Sub(userToken.RefreshAt) > 0 {
		userToken.CreateAt = gtime.Now()
		userToken.ExpireAt = userToken.CreateAt.Add(m.ExpireIn)
		userToken.RefreshAt = userToken.CreateAt.Add(m.ExpireIn / 2)
		if ok, err1 := m.setCache(ctx, userToken); ok {
			return userToken, nil
		} else {
			return nil, err1
		}
	}

	return userToken, nil
}

// encrypt return a valid token
func (m *GToken) encrypt(userKey string) (*UserToken, error) {
	if userKey == "" {
		return nil, fmt.Errorf(errorUserKeyEmpty)
	}
	tokenId := GetNanoId(m.TokenIdLength)
	jwtToken := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{ID: tokenId, Issuer: userKey},
	)
	token, err := jwtToken.SignedString(m.SecretKey)
	if err != nil {
		return nil, fmt.Errorf(errorTokenEncrypt)
	}
	return &UserToken{
		ID:      tokenId,
		UserKey: userKey,
		Token:   token,
	}, nil
}

// decrypt returns userKey and tokenId
func (m *GToken) decrypt(token string) (userKey string, tokenId string, err error) {
	if token == "" {
		return "", "", fmt.Errorf(errorTokenEmpty)
	}
	parse, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return m.SecretKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return
	}
	if !parse.Valid {
		return "", "", fmt.Errorf(errorTokenDecode)
	}
	return parse.Claims.(*jwt.RegisteredClaims).Issuer, parse.Claims.(*jwt.RegisteredClaims).ID, nil
}
