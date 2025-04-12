package gtoken

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/database/gredis"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
	"github.com/gogf/gf/v2/os/gfile"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/util/gconv"
)

func (m *GToken) setCache(ctx context.Context, userToken *UserToken) (ok bool, err error) {
	// Here we use userKey as cache key
	// Which means a user could have only one token at the same time, even if in multi-login
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		err = gcache.Set(ctx, userToken.UserKey, userToken, m.ExpireIn)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s, %v", errorSetCache, err), LogLevelError)
			return false, fmt.Errorf(errorSetCache)
		}
		if m.CacheMode == CacheModeFile {
			m.saveToFile(ctx)
		}
	case CacheModeRedis:
		cacheValueJson, err1 := gjson.Encode(userToken)
		if err1 != nil {
			WriteLog(ctx, fmt.Sprintf("%s, %v", errorEncodeCache, err1), LogLevelError)
			return false, fmt.Errorf(errorEncodeCache)
		}
		// g.Redis().SetEx() only support ttl in seconds
		// to make it the same as gcache which is in milliseconds, we use g.Redis().Set()
		expireIn := m.ExpireIn.Milliseconds()
		_, err = g.Redis().Set(ctx, userToken.UserKey, cacheValueJson, gredis.SetOption{TTLOption: gredis.TTLOption{PX: &expireIn}})
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s, %v", errorSetCache, err), LogLevelError)
			return false, fmt.Errorf(errorSetCache)
		}
	default:
		return false, fmt.Errorf(errorInvalidMode)
	}

	return true, nil
}

func (m *GToken) getCache(ctx context.Context, userKey string) (*UserToken, error) {
	var userToken UserToken
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		userCacheValue, err := gcache.Get(ctx, userKey)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s, %v", errorGetCache, err), LogLevelError)
			return nil, fmt.Errorf(errorGetCache)
		}
		if userCacheValue.IsNil() {
			return nil, fmt.Errorf(errorTokenNotFound)
		}
		err = userCacheValue.Scan(&userToken)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s, %v", errorDecodeCache, err), LogLevelError)
			return nil, fmt.Errorf(errorGetCache)
		}
	case CacheModeRedis:
		// you can use the following code to check ttl in milliseconds
		// res, err := g.Redis().Do(ctx, "PTTL", userKey)
		userCacheJson, err := g.Redis().Get(ctx, userKey)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s, %v", errorGetCache, err), LogLevelError)
			return nil, fmt.Errorf(errorGetCache)
		}
		if userCacheJson.IsNil() {
			return nil, fmt.Errorf(errorTokenNotFound)
		}
		err = userCacheJson.Scan(&userToken)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s, %v", errorDecodeCache, err), LogLevelError)
			return nil, fmt.Errorf(errorDecodeCache)
		}
	default:
		return nil, fmt.Errorf(errorInvalidMode)
	}

	return &userToken, nil
}

func (m *GToken) removeCache(ctx context.Context, userKey string) (ok bool, err error) {
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		_, err = gcache.Remove(ctx, userKey)
		if err != nil {
			g.Log().Error(ctx, err)
		}
		if m.CacheMode == CacheModeFile {
			m.saveToFile(ctx)
		}
	case CacheModeRedis:
		_, err = g.Redis().Del(ctx, userKey)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s, %v", errorDeleteCache, err), LogLevelError)
			return false, fmt.Errorf(errorDeleteCache)
		}
	default:
		return false, fmt.Errorf(errorInvalidMode)
	}

	return true, nil
}

func (m *GToken) saveToFile(ctx context.Context) {
	file := gfile.Temp(CacheModeFileDat)
	data, err := gcache.Data(ctx)
	if err != nil {
		WriteLog(ctx, fmt.Sprintf("%s, %v", errorGetCache, err), LogLevelError)
	}
	err = gfile.PutContents(file, gjson.New(data).MustToJsonString())
	if err != nil {
		WriteLog(ctx, fmt.Sprintf("%s, %v", errorWriteFile, err), LogLevelError)
	}
}

func (m *GToken) initCacheModeFile(ctx context.Context) {
	file := gfile.Temp(CacheModeFileDat)
	if !gfile.Exists(file) {
		return
	}
	data := gfile.GetContents(file)
	maps := gconv.Map(data)
	if maps == nil || len(maps) <= 0 {
		return
	}
	for k, v := range maps {
		// Avoid using m.ExpireIn
		// Since loading tokens from files, the interval should not be reset
		var token UserToken
		err := gconv.Struct(v, &token)
		if err != nil {
			continue
		}
		tokenExpireIn := token.ExpireAt.Sub(gtime.Now())
		if tokenExpireIn <= 0 {
			continue
		}
		err = gcache.Set(ctx, k, v, tokenExpireIn)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s, %v", errorSetCache, err), LogLevelError)
		}
	}
}
