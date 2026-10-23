package gtoken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
)

const (
	redisRefreshSuccess  = 1
	redisRefreshRejected = -1
	redisRefreshExpired  = -2
	redisRefreshReplay   = -3
	redisRefreshChanged  = -4
)

const redisCreateFamilyScript = `
if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[3])
return 1
`

// All JSON decoding, authorization, and payload encoding happen in Go. Redis
// compares the exact validated snapshot before applying the transition atomically.
const redisRefreshFamilyScript = `
local raw = redis.call('GET', KEYS[1])
if not raw then return -1 end
if raw ~= ARGV[1] then return -4 end
local outcome = tonumber(ARGV[2])
if outcome == -3 then
  redis.call('SET', KEYS[1], ARGV[10], 'PX', ARGV[6])
  return -3
end
if outcome ~= 1 then return outcome end
redis.call('SET', KEYS[1], ARGV[3], 'PX', ARGV[6])
redis.call('DEL', KEYS[2])
redis.call('SET', KEYS[3], ARGV[4], 'PX', ARGV[7])
redis.call('SET', KEYS[4], ARGV[5], 'PX', ARGV[6])
redis.call('SREM', KEYS[5], ARGV[8])
redis.call('SADD', KEYS[5], ARGV[9])
redis.call('PEXPIRE', KEYS[5], ARGV[7])
return 1
`

const redisRevokeFamilyScript = `
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
if raw ~= ARGV[1] then return -4 end
redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
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
	family, _, err := m.getTokenFamilySnapshotRedis(ctx, familyID)
	return family, err
}

func (m *GToken) getTokenFamilySnapshotRedis(ctx context.Context, familyID string) (*TokenFamily, string, error) {
	value, err := g.Redis().Get(ctx, DefaultPrefixFamily+familyID)
	if err != nil || value.IsNil() {
		return nil, "", ErrRefreshTokenRejected
	}
	raw := value.String()
	family := &TokenFamily{}
	if err = json.Unmarshal([]byte(raw), family); err != nil {
		return nil, "", ErrRefreshTokenRejected
	}
	return family, raw, nil
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

var errRedisFamilyChanged = errors.New("token family changed during atomic update")

func (m *GToken) refreshTokenPairRedis(ctx context.Context, familyID string, digest [sha256.Size]byte, expectedExtraData g.Map) (*TokenPair, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pair, err := m.refreshTokenPairSnapshotRedis(ctx, familyID, digest, expectedExtraData)
		if !errors.Is(err, errRedisFamilyChanged) {
			return pair, err
		}
	}
}

func (m *GToken) refreshTokenPairSnapshotRedis(ctx context.Context, familyID string, digest [sha256.Size]byte, expectedExtraData g.Map) (*TokenPair, error) {
	family, raw, err := m.getTokenFamilySnapshotRedis(ctx, familyID)
	if err != nil || !refreshDigestMatches(family.RefreshDigest, digest) || !expectedExtraDataMatches(family.ExtraData, expectedExtraData) {
		return nil, ErrRefreshTokenRejected
	}
	now := m.now()
	outcome := redisRefreshRejected
	switch family.State {
	case tokenFamilyStateConsumed, tokenFamilyStateRevoked:
		outcome = redisRefreshReplay
	case tokenFamilyStateActive:
		outcome = redisRefreshSuccess
		if family.RefreshExpiresAtMillis <= now.UnixMilli() {
			outcome = redisRefreshExpired
		}
	}
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
	revoked := *family
	revoked.State = tokenFamilyStateRevoked
	revokedJSON, err := gjson.Encode(&revoked)
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
			raw, outcome,
			consumedJSON, successorJSON, indexJSON, familyTTL, accessTTL,
			family.CurrentAccessTokenID, successorID, revokedJSON,
		},
	)
	if err != nil {
		return nil, err
	}
	code := result.Int()
	if code == redisRefreshChanged {
		return nil, errRedisFamilyChanged
	}
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
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			family, raw, err := m.getTokenFamilySnapshotRedis(ctx, familyID)
			if err != nil {
				break
			}
			if digest != "" && family.RefreshDigest != digest {
				break
			}
			family.State = tokenFamilyStateRevoked
			revokedJSON, err := gjson.Encode(family)
			if err != nil {
				return err
			}
			ttl := family.FamilyExpiresAt.Time.Sub(m.now()).Milliseconds()
			if ttl <= 0 {
				break
			}
			result, evalErr := g.Redis().Eval(ctx, redisRevokeFamilyScript, 1,
				[]string{DefaultPrefixFamily + familyID}, []any{raw, revokedJSON, ttl})
			if evalErr != nil {
				return evalErr
			}
			if result.Int() == redisRefreshChanged {
				continue
			}
			if result.Int() == 1 {
				_ = m.removeAccessTokenRedisByID(ctx, family.UserID, family.CurrentAccessTokenID)
				_ = m.removeAccessTokenRedisByID(ctx, family.UserID, family.SuccessorAccessTokenID)
			}
			break
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
