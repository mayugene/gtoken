package gtoken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
)

const (
	redisRefreshSuccess  = 1
	redisRefreshRejected = -1
	redisRefreshExpired  = -2
	redisRefreshReplay   = -3
)

const redisCreateFamilyScript = `
if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[3])
return 1
`

const redisRefreshFamilyScript = `
local raw = redis.call('GET', KEYS[1])
if not raw then return -1 end
local family = cjson.decode(raw)
if family.refreshDigest ~= ARGV[1] then return -1 end
local expected = cjson.decode(ARGV[2])
for key, value in pairs(expected) do
  if family.extraData == nil or family.extraData[key] == nil or tostring(family.extraData[key]) ~= tostring(value) then return -1 end
end
if family.state == 'consumed' or family.state == 'revoked' then
  family.state = 'revoked'
  redis.call('SET', KEYS[1], cjson.encode(family), 'PX', ARGV[7])
  return -3
end
if family.state ~= 'active' then return -1 end
if tonumber(family.refreshExpiresAtMillis) <= tonumber(ARGV[3]) then return -2 end
redis.call('SET', KEYS[1], ARGV[4], 'PX', ARGV[7])
redis.call('DEL', KEYS[2])
redis.call('SET', KEYS[3], ARGV[5], 'PX', ARGV[8])
redis.call('SET', KEYS[4], ARGV[6], 'PX', ARGV[7])
redis.call('SREM', KEYS[5], ARGV[9])
redis.call('SADD', KEYS[5], ARGV[10])
redis.call('PEXPIRE', KEYS[5], ARGV[8])
return 1
`

const redisRevokeFamilyScript = `
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local family = cjson.decode(raw)
if ARGV[1] ~= '' and family.refreshDigest ~= ARGV[1] then return 0 end
family.state = 'revoked'
redis.call('SET', KEYS[1], cjson.encode(family), 'PX', ARGV[2])
return 1
`

func redisRefreshError(code int) error {
	switch code {
	case redisRefreshSuccess:
		return nil
	case redisRefreshExpired:
		return ErrRefreshTokenExpired
	case redisRefreshReplay:
		return ErrRefreshTokenReplay
	default:
		return ErrRefreshTokenRejected
	}
}

func (m *GToken) createTokenFamilyRedis(ctx context.Context, family *TokenFamily, accessTokenID string) error {
	familyJSON, err := gjson.Encode(family)
	if err != nil {
		return err
	}
	indexJSON, err := gjson.Encode(accessFamilyIndex{FamilyID: family.FamilyID, ExpireAt: family.FamilyExpiresAt})
	if err != nil {
		return err
	}
	ttl := family.FamilyExpiresAt.Time.Sub(m.now()).Milliseconds()
	if ttl <= 0 {
		return ErrRefreshTokenExpired
	}
	result, err := g.Redis().Eval(ctx, redisCreateFamilyScript, 2,
		[]string{DefaultPrefixFamily + family.FamilyID, DefaultPrefixAccess + accessTokenID},
		[]any{familyJSON, indexJSON, ttl},
	)
	if err != nil {
		return err
	}
	return redisRefreshError(result.Int())
}

func (m *GToken) getTokenFamilyRedis(ctx context.Context, familyID string) (*TokenFamily, error) {
	value, err := g.Redis().Get(ctx, DefaultPrefixFamily+familyID)
	if err != nil || value.IsNil() {
		return nil, ErrRefreshTokenRejected
	}
	family := &TokenFamily{}
	if err = value.Scan(family); err != nil {
		return nil, ErrRefreshTokenRejected
	}
	return family, nil
}

func (m *GToken) getAccessFamilyIndexRedis(ctx context.Context, tokenID string) (string, error) {
	value, err := g.Redis().Get(ctx, DefaultPrefixAccess+tokenID)
	if err != nil || value.IsNil() {
		return "", ErrRefreshTokenRejected
	}
	index := &accessFamilyIndex{}
	if err = value.Scan(index); err != nil || index.FamilyID == "" {
		return "", ErrRefreshTokenRejected
	}
	return index.FamilyID, nil
}

func (m *GToken) refreshTokenPairRedis(ctx context.Context, familyID string, digest [sha256.Size]byte, expectedExtraData g.Map) (*TokenPair, error) {
	family, err := m.getTokenFamilyRedis(ctx, familyID)
	if err != nil {
		return nil, ErrRefreshTokenRejected
	}
	now := m.now()
	successorToken, successorID, err := m.encrypt()
	if err != nil {
		return nil, err
	}
	successorInfo := &TokenInfo{
		UserID: family.UserID, TokenID: successorID, ExtraData: family.ExtraData,
		ExpireAt: gtime.New(now.Add(m.ExpireIn)), RefreshAt: gtime.New(now.Add(m.ExpireIn)), FamilyID: family.FamilyID,
	}
	consumed := *family
	consumed.State = tokenFamilyStateConsumed
	consumed.SuccessorAccessTokenID = successorID
	consumedJSON, err := gjson.Encode(&consumed)
	if err != nil {
		return nil, err
	}
	successorJSON, err := gjson.Encode(successorInfo)
	if err != nil {
		return nil, err
	}
	indexJSON, err := gjson.Encode(accessFamilyIndex{FamilyID: family.FamilyID, ExpireAt: family.FamilyExpiresAt})
	if err != nil {
		return nil, err
	}
	expected := expectedExtraData
	if expected == nil {
		expected = g.Map{}
	}
	expectedJSON, err := gjson.Encode(expected)
	if err != nil {
		return nil, err
	}
	oldToken, err := encryptJWT(m.SecretKey, family.CurrentAccessTokenID)
	if err != nil {
		return nil, err
	}
	familyTTL := family.FamilyExpiresAt.Time.Sub(now).Milliseconds()
	accessTTL := m.ExpireIn.Milliseconds()
	result, err := g.Redis().Eval(ctx, redisRefreshFamilyScript, 5,
		[]string{
			DefaultPrefixFamily + familyID,
			DefaultPrefixToken + oldToken,
			DefaultPrefixToken + successorToken,
			DefaultPrefixAccess + successorID,
			DefaultPrefixUser + family.UserID,
		},
		[]any{
			base64.RawURLEncoding.EncodeToString(digest[:]), expectedJSON, now.UnixMilli(),
			consumedJSON, successorJSON, indexJSON, familyTTL, accessTTL,
			family.CurrentAccessTokenID, successorID,
		},
	)
	if err != nil {
		return nil, err
	}
	code := result.Int()
	if code == redisRefreshReplay {
		if replayed, replayErr := m.getTokenFamilyRedis(ctx, familyID); replayErr == nil {
			_ = m.removeAccessTokenRedisByID(ctx, replayed.UserID, replayed.SuccessorAccessTokenID)
		}
	}
	if err = redisRefreshError(code); err != nil {
		return nil, err
	}
	return &TokenPair{AccessToken: successorToken, AccessTokenInfo: successorInfo}, nil
}

func (m *GToken) revokeTokenFamilyRedis(ctx context.Context, accessToken string, refreshToken string) error {
	familyDigests := make(map[string]string)
	if accessToken != "" {
		if tokenID, err := decryptJWT(m.SecretKey, accessToken); err == nil {
			if familyID, indexErr := m.getAccessFamilyIndexRedis(ctx, tokenID); indexErr == nil {
				familyDigests[familyID] = ""
			}
		}
	}
	if refreshToken != "" {
		if familyID, secret, err := parseRefreshCredential(refreshToken); err == nil {
			if _, authorizedByAccess := familyDigests[familyID]; !authorizedByAccess {
				digest := digestRefreshSecret(secret)
				familyDigests[familyID] = base64.RawURLEncoding.EncodeToString(digest[:])
			}
		}
	}
	for familyID, digest := range familyDigests {
		family, err := m.getTokenFamilyRedis(ctx, familyID)
		if err != nil {
			continue
		}
		ttl := family.FamilyExpiresAt.Time.Sub(m.now()).Milliseconds()
		if ttl <= 0 {
			continue
		}
		result, evalErr := g.Redis().Eval(ctx, redisRevokeFamilyScript, 1,
			[]string{DefaultPrefixFamily + familyID}, []any{digest, ttl})
		if evalErr != nil {
			return evalErr
		}
		if result.Int() == 1 {
			_ = m.removeAccessTokenRedisByID(ctx, family.UserID, family.CurrentAccessTokenID)
			_ = m.removeAccessTokenRedisByID(ctx, family.UserID, family.SuccessorAccessTokenID)
		}
	}
	return nil
}

func (m *GToken) removeAccessTokenRedisByID(ctx context.Context, userID string, tokenID string) error {
	if tokenID == "" {
		return nil
	}
	token, err := encryptJWT(m.SecretKey, tokenID)
	if err != nil {
		return err
	}
	if _, err = g.Redis().Del(ctx, DefaultPrefixToken+token); err != nil {
		return err
	}
	_, err = g.Redis().SRem(ctx, DefaultPrefixUser+userID, tokenID)
	return err
}
