package gtoken

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
	"github.com/gogf/gf/v2/os/gtime"
)

type accessFamilyIndex struct {
	FamilyID string      `json:"familyID"`
	ExpireAt *gtime.Time `json:"expireAt"`
}

func (m *GToken) createTokenFamilyCache(ctx context.Context, family *TokenFamily) error {
	ttl := family.FamilyExpiresAt.Time.Sub(m.now())
	if ttl <= 0 {
		return ErrRefreshTokenExpired
	}
	return gcache.Set(ctx, DefaultPrefixFamily+family.FamilyID, family, ttl)
}

func (m *GToken) getTokenFamilyCache(ctx context.Context, familyID string) (*TokenFamily, error) {
	value, err := gcache.Get(ctx, DefaultPrefixFamily+familyID)
	if err != nil || value.IsNil() {
		return nil, ErrRefreshTokenRejected
	}
	family := &TokenFamily{}
	if err = value.Scan(family); err != nil {
		return nil, ErrRefreshTokenRejected
	}
	return family, nil
}

func (m *GToken) setAccessFamilyIndexCache(ctx context.Context, accessTokenID string, familyID string, expireAt *gtime.Time) error {
	ttl := expireAt.Time.Sub(m.now())
	if ttl <= 0 {
		return ErrRefreshTokenExpired
	}
	return gcache.Set(ctx, DefaultPrefixAccess+accessTokenID, accessFamilyIndex{FamilyID: familyID, ExpireAt: expireAt}, ttl)
}

func (m *GToken) getAccessFamilyIndexCache(ctx context.Context, accessTokenID string) (string, error) {
	value, err := gcache.Get(ctx, DefaultPrefixAccess+accessTokenID)
	if err != nil || value.IsNil() {
		return "", ErrRefreshTokenRejected
	}
	index := &accessFamilyIndex{}
	if err = value.Scan(index); err != nil || index.FamilyID == "" {
		return "", ErrRefreshTokenRejected
	}
	return index.FamilyID, nil
}

func (m *GToken) removeTokenFamilyRecordCache(ctx context.Context, familyID string) {
	_, _ = gcache.Remove(ctx, DefaultPrefixFamily+familyID)
}

func (m *GToken) refreshTokenPairCache(ctx context.Context, familyID string, presentedDigest [sha256.Size]byte, expectedExtraData g.Map) (*TokenPair, error) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	family, err := m.getTokenFamilyCache(ctx, familyID)
	if err != nil || !refreshDigestMatches(family.RefreshDigest, presentedDigest) {
		return nil, ErrRefreshTokenRejected
	}
	if !expectedExtraDataMatches(family.ExtraData, expectedExtraData) {
		return nil, ErrRefreshTokenRejected
	}
	if family.State == tokenFamilyStateConsumed || family.State == tokenFamilyStateRevoked {
		family.State = tokenFamilyStateRevoked
		_ = m.createTokenFamilyCache(ctx, family)
		_ = m.removeAccessTokenByID(ctx, family.SuccessorAccessTokenID)
		if m.CacheMode == CacheModeFile {
			if saveErr := m.saveToFile(ctx); saveErr != nil {
				return nil, saveErr
			}
		}
		return nil, ErrRefreshTokenReplay
	}
	if family.State != tokenFamilyStateActive {
		return nil, ErrRefreshTokenRejected
	}
	if !family.RefreshExpiresAt.Time.After(m.now()) {
		return nil, ErrRefreshTokenExpired
	}

	successorToken, successorInfo, err := m.NewToken(ctx, family.UserID, family.ExtraData)
	if err != nil {
		return nil, err
	}
	successorInfo.FamilyID = family.FamilyID
	if ok, refreshErr := m.refreshTokenCache(ctx, successorToken, successorInfo); !ok {
		_, _ = m.removeTokenCache(ctx, successorToken)
		return nil, refreshErr
	}
	if err = m.setAccessFamilyIndexCache(ctx, successorInfo.TokenID, family.FamilyID, family.FamilyExpiresAt); err != nil {
		_, _ = m.removeTokenCache(ctx, successorToken)
		return nil, err
	}

	previousState := family.State
	family.State = tokenFamilyStateConsumed
	family.SuccessorAccessTokenID = successorInfo.TokenID
	if err = m.createTokenFamilyCache(ctx, family); err != nil {
		family.State = previousState
		_, _ = m.removeTokenCache(ctx, successorToken)
		return nil, err
	}
	if err = m.removeAccessTokenByID(ctx, family.CurrentAccessTokenID); err != nil {
		family.State = previousState
		family.SuccessorAccessTokenID = ""
		_ = m.createTokenFamilyCache(ctx, family)
		_, _ = m.removeTokenCache(ctx, successorToken)
		return nil, err
	}
	if m.CacheMode == CacheModeFile {
		if err = m.saveToFile(ctx); err != nil {
			family.State = tokenFamilyStateRevoked
			_ = m.removeAccessTokenByID(ctx, successorInfo.TokenID)
			return nil, err
		}
	}
	return &TokenPair{AccessToken: successorToken, AccessTokenInfo: successorInfo}, nil
}

func (m *GToken) revokeTokenFamilyCache(ctx context.Context, accessToken string, refreshToken string) error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	familyIDs := make(map[string]struct{})
	if accessToken != "" {
		if tokenID, err := decryptJWT(m.SecretKey, accessToken); err == nil {
			if familyID, indexErr := m.getAccessFamilyIndexCache(ctx, tokenID); indexErr == nil {
				familyIDs[familyID] = struct{}{}
			}
		}
	}
	if refreshToken != "" {
		if familyID, secret, err := parseRefreshCredential(refreshToken); err == nil {
			if family, familyErr := m.getTokenFamilyCache(ctx, familyID); familyErr == nil {
				digest := digestRefreshSecret(secret)
				if refreshDigestMatches(family.RefreshDigest, digest) {
					familyIDs[familyID] = struct{}{}
				}
			}
		}
	}

	for familyID := range familyIDs {
		family, err := m.getTokenFamilyCache(ctx, familyID)
		if err != nil {
			continue
		}
		family.State = tokenFamilyStateRevoked
		_ = m.removeAccessTokenByID(ctx, family.CurrentAccessTokenID)
		_ = m.removeAccessTokenByID(ctx, family.SuccessorAccessTokenID)
		_ = m.createTokenFamilyCache(ctx, family)
	}
	if m.CacheMode == CacheModeFile {
		if err := m.saveToFile(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (m *GToken) removeAccessTokenByID(ctx context.Context, tokenID string) error {
	if tokenID == "" {
		return nil
	}
	token, err := encryptJWT(m.SecretKey, tokenID)
	if err != nil {
		return err
	}
	if _, err = m.getTokenCache(ctx, token); err != nil {
		return nil
	}
	ok, err := m.removeTokenCache(ctx, token)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New(errorDeleteCache)
	}
	return nil
}
