package gtoken

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/container/gset"
	"github.com/gogf/gf/v2/container/gvar"
	"github.com/gogf/gf/v2/database/gredis"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
	"github.com/gogf/gf/v2/os/gfile"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/util/gconv"
	"strings"
)

func (m *GToken) setTokenCache(ctx context.Context, token string, tokenInfo *TokenInfo) (ok bool, err error) {
	/*
		1. set key: "jwt:{token}",   value: tokenInfo
		2. get the value of "user:{userId}" (format: []string of tokenId), check if each tokenId has expired, and reformat the slice
		3. set key: "user:{userId}", value: the valid tokenId slice
	*/
	tokenKey := fmt.Sprintf("%s%s", DefaultPrefixToken, token)
	userKey := fmt.Sprintf("%s%s", DefaultPrefixUser, tokenInfo.UserID)
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		// step 1: set token info
		err = gcache.Set(ctx, tokenKey, tokenInfo, m.ExpireIn)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorSetCache, err), LogLevelError)
			return false, err
		}
		// step 2: use userKey to get all token IDs as a set
		// if tokens expire, remove their IDs from this set
		tokenIdVar, err1 := gcache.Get(ctx, userKey)
		if err1 != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorGetCache, err1), LogLevelError)
			return false, err1
		}
		tokenIdSlice := gconv.Strings(tokenIdVar.Val())
		existedTokenIdSet := gset.NewStrSet()
		for _, id := range tokenIdSlice {
			jwtToken, err2 := encryptJWT(m.SecretKey, id)
			if err2 != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorTokenEncrypt, err2), LogLevelError)
				return false, err2
			}
			idExists, err2 := gcache.Contains(ctx, jwtToken)
			if err2 != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorUseCache, err2), LogLevelError)
				return false, err2
			}
			if idExists {
				existedTokenIdSet.Add(id)
			}
		}
		// step 3: add the new token into this set and refresh its ttl
		existedTokenIdSet.Add(tokenInfo.TokenID)
		err = gcache.Set(ctx, userKey, existedTokenIdSet.Slice(), m.ExpireIn)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorSetCache, err), LogLevelError)
			return false, err
		}
		// keep file content up-to-date
		if m.CacheMode == CacheModeFile {
			saveToFile(ctx)
		}
	case CacheModeRedis:
		cacheValueJson, err1 := gjson.Encode(tokenInfo)
		if err1 != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorEncodeJson, err1), LogLevelError)
			return false, err1
		}
		// g.Redis().SetEx() only support ttl in seconds
		// to make it the same as gcache which is in milliseconds, we use g.Redis().Set()
		expireIn := m.ExpireIn.Milliseconds()
		// step 1: set token info
		_, err = g.Redis().Set(ctx, tokenKey, cacheValueJson, gredis.SetOption{TTLOption: gredis.TTLOption{PX: &expireIn}})
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorSetCache, err), LogLevelError)
			return false, err
		}
		// step 2: find all members which are the token IDs in redis set
		// if tokens expire, remove their IDs from this set
		tokenIdVar, err1 := g.Redis().SMembers(ctx, userKey)
		if err1 != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorUseRedis, err1), LogLevelError)
			return false, err1
		}
		for _, id := range tokenIdVar.Strings() {
			jwtToken, err2 := encryptJWT(m.SecretKey, id)
			if err2 != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorTokenEncrypt, err2), LogLevelError)
				return false, err2
			}
			counts, err2 := g.Redis().Exists(ctx, jwtToken)
			if err2 != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorUseRedis, err2), LogLevelError)
				return false, err2
			}
			if counts > 0 {
				continue
			}
			_, err2 = g.Redis().SRem(ctx, userKey, id)
			if err2 != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorUseRedis, err2), LogLevelError)
				return false, err2
			}
		}
		// step 3: add the new token into this set and refresh its ttl
		_, err = g.Redis().SAdd(ctx, userKey, tokenInfo.TokenID)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorUseRedis, err), LogLevelError)
			return false, err
		}
		_, err = g.Redis().PExpire(ctx, userKey, expireIn)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorUseRedis, err), LogLevelError)
			return false, err
		}
	default:
		return false, fmt.Errorf(errorInvalidMode)
	}

	return true, nil
}

func (m *GToken) getTokenCache(ctx context.Context, token string) (tokenInfo *TokenInfo, err error) {
	tokenKey := fmt.Sprintf("%s%s", DefaultPrefixToken, token)

	var cacheValue *gvar.Var

	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		cacheValue, err = gcache.Get(ctx, tokenKey)
	case CacheModeRedis:
		cacheValue, err = g.Redis().Get(ctx, tokenKey)
	default:
		return nil, fmt.Errorf(errorInvalidMode)
	}
	if err != nil {
		WriteLog(ctx, fmt.Sprintf("%s: %v", errorGetCache, err), LogLevelError)
		return nil, err
	}
	if cacheValue.IsNil() {
		return nil, fmt.Errorf(errorTokenNotFound)
	}
	tokenInfo = &TokenInfo{} // make sure to assign memory or tokenInfo is nil
	err = cacheValue.Scan(tokenInfo)
	if err != nil {
		WriteLog(ctx, fmt.Sprintf("%s: %v", errorDecodeCache, err), LogLevelError)
		return nil, err
	}

	return
}

func (m *GToken) refreshTokenCache(ctx context.Context, token string, tokenInfo *TokenInfo) (ok bool, err error) {
	tokenKey := fmt.Sprintf("%s%s", DefaultPrefixToken, token)
	userKey := fmt.Sprintf("%s%s", DefaultPrefixUser, tokenInfo.UserID)
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		// set token info
		err = gcache.Set(ctx, tokenKey, tokenInfo, m.ExpireIn)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorSetCache, err), LogLevelError)
			return false, err
		}
		// refresh user key ttl
		_, err = gcache.UpdateExpire(ctx, userKey, m.ExpireIn)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorSetCache, err), LogLevelError)
			return false, err
		}
		// keep file content up-to-date
		if m.CacheMode == CacheModeFile {
			saveToFile(ctx)
		}
	case CacheModeRedis:
		cacheValueJson, err1 := gjson.Encode(tokenInfo)
		if err1 != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorEncodeJson, err1), LogLevelError)
			return false, err1
		}
		expireIn := m.ExpireIn.Milliseconds()
		// set token info
		_, err = g.Redis().Set(ctx, tokenKey, cacheValueJson, gredis.SetOption{TTLOption: gredis.TTLOption{PX: &expireIn}})
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorUseRedis, err), LogLevelError)
			return false, err
		}
		// token ID is not changed, so just refresh ttl
		_, err = g.Redis().PExpire(ctx, userKey, expireIn)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorUseRedis, err), LogLevelError)
			return false, err
		}
	default:
		return false, fmt.Errorf(errorInvalidMode)
	}

	return true, nil
}

func (m *GToken) removeTokenCache(ctx context.Context, token string) (ok bool, err error) {
	/*
		1. get tokenInfo by token
		2. remove token
		3. remove tokenId from userKey
	*/
	a, _ := gcache.Data(ctx)
	fmt.Println(a)
	tokenInfo, err := m.getTokenCache(ctx, token)
	if err != nil {
		return false, err
	}
	tokenKey := fmt.Sprintf("%s%s", DefaultPrefixToken, token)
	userKey := fmt.Sprintf("%s%s", DefaultPrefixUser, tokenInfo.UserID)

	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		// remove token
		_, err = gcache.Remove(ctx, tokenKey)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorDeleteCache, err), LogLevelError)
			return false, err
		}
		// remove token id from userKey
		tokenIdVar, err1 := gcache.Get(ctx, userKey)
		if err1 != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorGetCache, err1), LogLevelError)
			return false, err1
		}
		tokenIdSlice := gconv.Strings(tokenIdVar.Val())
		existedTokenIdSet := gset.NewStrSetFrom(tokenIdSlice)
		existedTokenIdSet.Remove(tokenInfo.TokenID)
		if existedTokenIdSet.Size() == 0 {
			_, err = gcache.Remove(ctx, userKey)
			if err != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorDeleteCache, err), LogLevelError)
				return false, err
			}
		} else {
			err = gcache.Set(ctx, userKey, existedTokenIdSet.Slice(), m.ExpireIn) // maybe it's OK to not use the real ttl here
			if err != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorSetCache, err), LogLevelError)
				return false, err
			}
		}
		// keep file content up-to-date
		if m.CacheMode == CacheModeFile {
			saveToFile(ctx)
		}
	case CacheModeRedis:
		// remove token
		_, err = g.Redis().Del(ctx, tokenKey)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorDeleteCache, err), LogLevelError)
			return false, err
		}
		// remove token id from user key
		_, err = g.Redis().SRem(ctx, userKey, tokenInfo.TokenID)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorDeleteCache, err), LogLevelError)
			return false, err
		}
	default:
		return false, fmt.Errorf(errorInvalidMode)
	}

	return true, nil
}

func (m *GToken) removeUserCache(ctx context.Context, userId string) (ok bool, err error) {
	userKey := fmt.Sprintf("%s%s", DefaultPrefixUser, userId)
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		// get cached value
		tokenIdVar, err1 := gcache.Get(ctx, userKey)
		if err1 != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorDeleteCache, err), LogLevelError)
			return false, err1
		}
		// remove userKey before removing every token to avoid some error cases
		_, err = gcache.Remove(ctx, userKey)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorDeleteCache, err), LogLevelError)
			return false, err
		}
		tokenIdSlice := gconv.Strings(tokenIdVar.Val())
		// remove related tokens
		for _, id := range tokenIdSlice {
			jwtToken, err2 := encryptJWT(m.SecretKey, id)
			if err2 != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorTokenEncrypt, err2), LogLevelError)
				return false, err2
			}
			tokenKey := fmt.Sprintf("%s%s", DefaultPrefixToken, jwtToken)
			_, err = gcache.Remove(ctx, tokenKey)
			if err != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorDeleteCache, err), LogLevelError)
				return false, err
			}
		}
		// keep file content up-to-date
		if m.CacheMode == CacheModeFile {
			saveToFile(ctx)
		}
	case CacheModeRedis:
		// get cached value
		tokenIdVar, err1 := g.Redis().Get(ctx, userKey)
		if err1 != nil {
			return false, err1
		}
		// remove userKey before removing every token to avoid some error cases
		_, err = g.Redis().Del(ctx, userKey)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorDeleteCache, err), LogLevelError)
			return false, err
		}
		tokenIdSlice := gconv.Strings(tokenIdVar.Val())
		// remove related token
		for _, id := range tokenIdSlice {
			jwtToken, err2 := encryptJWT(m.SecretKey, id)
			if err2 != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorTokenEncrypt, err2), LogLevelError)
				return false, err2
			}
			tokenKey := fmt.Sprintf("%s%s", DefaultPrefixToken, jwtToken)
			_, err = g.Redis().Del(ctx, tokenKey)
			if err != nil {
				WriteLog(ctx, fmt.Sprintf("%s: %v", errorDeleteCache, err), LogLevelError)
				return false, err
			}
		}

	default:
		return false, fmt.Errorf(errorInvalidMode)
	}

	return true, nil
}

func saveToFile(ctx context.Context) {
	file := gfile.Temp(CacheModeFileDat)
	data, err := gcache.Data(ctx)
	if err != nil {
		WriteLog(ctx, fmt.Sprintf("%s: %v", errorGetCache, err), LogLevelError)
	}
	err = gfile.PutContents(file, gjson.New(data).MustToJsonString())
	if err != nil {
		WriteLog(ctx, fmt.Sprintf("%s: %v", errorWriteFile, err), LogLevelError)
	}
}

func initCacheModeFile(ctx context.Context) {
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
		if !strings.HasPrefix(k, DefaultPrefixToken) {
			continue
		}
		var token TokenInfo
		err := gconv.Struct(v, &token)
		if err != nil {
			continue
		}
		expireIn := token.ExpireAt.Sub(gtime.Now())
		if expireIn <= 0 {
			continue
		}
		err = gcache.Set(ctx, k, v, expireIn)
		if err != nil {
			WriteLog(ctx, fmt.Sprintf("%s: %v", errorSetCache, err), LogLevelError)
		}
	}
}
