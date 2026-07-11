package gtoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/util/gconv"
)

var (
	ErrRefreshTokenRejected = errors.New("refresh token rejected")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrRefreshTokenReplay   = errors.New("refresh token replay")
)

const (
	tokenFamilyStateActive   = "active"
	tokenFamilyStateConsumed = "consumed"
	tokenFamilyStateRevoked  = "revoked"
)

type TokenPair struct {
	AccessToken      string
	AccessTokenInfo  *TokenInfo
	RefreshToken     string
	RefreshExpiresAt *gtime.Time
}

type TokenFamily struct {
	FamilyID               string      `json:"familyID"`
	UserID                 string      `json:"userID"`
	ExtraData              g.Map       `json:"extraData"`
	RefreshDigest          string      `json:"refreshDigest"`
	CurrentAccessTokenID   string      `json:"currentAccessTokenID"`
	SuccessorAccessTokenID string      `json:"successorAccessTokenID,omitempty"`
	IssuedAt               *gtime.Time `json:"issuedAt"`
	RefreshExpiresAt       *gtime.Time `json:"refreshExpiresAt"`
	FamilyExpiresAt        *gtime.Time `json:"familyExpiresAt"`
	State                  string      `json:"state"`
}

func (m *GToken) now() time.Time {
	if m.Clock != nil {
		return m.Clock().UTC()
	}
	return time.Now().UTC()
}

func newRefreshCredential(familyID string) (string, [sha256.Size]byte, error) {
	secret := make([]byte, refreshSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", [sha256.Size]byte{}, err
	}
	digest := digestRefreshSecret(secret)
	return familyID + "." + base64.RawURLEncoding.EncodeToString(secret), digest, nil
}

func parseRefreshCredential(raw string) (string, []byte, error) {
	if strings.Count(raw, ".") != 1 {
		return "", nil, ErrRefreshTokenRejected
	}
	parts := strings.SplitN(raw, ".", 2)
	if parts[0] == "" {
		return "", nil, ErrRefreshTokenRejected
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(secret) != refreshSecretBytes {
		return "", nil, ErrRefreshTokenRejected
	}
	return parts[0], secret, nil
}

func digestRefreshSecret(secret []byte) [sha256.Size]byte {
	return sha256.Sum256(secret)
}

func (m *GToken) NewTokenPair(ctx context.Context, userID string, extraData g.Map) (*TokenPair, error) {
	if !m.Init(ctx) || m.AutoRefreshToken || m.RefreshLimit != 1 {
		return nil, ErrRefreshTokenRejected
	}
	if userID == "" {
		return nil, errors.New("a valid userId is required")
	}

	familyID := getNanoID(24)
	refreshToken, digest, err := newRefreshCredential(familyID)
	if err != nil {
		return nil, err
	}
	accessToken, accessInfo, err := m.NewToken(ctx, userID, extraData)
	if err != nil {
		return nil, err
	}
	accessInfo.FamilyID = familyID
	if ok, refreshErr := m.refreshTokenCache(ctx, accessToken, accessInfo); !ok {
		_, _ = m.removeTokenCache(ctx, accessToken)
		return nil, refreshErr
	}

	now := m.now()
	refreshExpiresAt := gtime.New(now.Add(m.RefreshExpireIn))
	family := &TokenFamily{
		FamilyID:             familyID,
		UserID:               userID,
		ExtraData:            extraData,
		RefreshDigest:        base64.RawURLEncoding.EncodeToString(digest[:]),
		CurrentAccessTokenID: accessInfo.TokenID,
		IssuedAt:             gtime.New(now),
		RefreshExpiresAt:     refreshExpiresAt,
		FamilyExpiresAt:      gtime.New(refreshExpiresAt.Time.Add(m.ExpireIn)),
		State:                tokenFamilyStateActive,
	}
	if err = m.createTokenFamilyCache(ctx, family); err != nil {
		_, _ = m.removeTokenCache(ctx, accessToken)
		return nil, err
	}
	if err = m.setAccessFamilyIndexCache(ctx, accessInfo.TokenID, familyID, family.FamilyExpiresAt); err != nil {
		m.removeTokenFamilyRecordCache(ctx, familyID)
		_, _ = m.removeTokenCache(ctx, accessToken)
		return nil, err
	}
	if m.CacheMode == CacheModeFile {
		if err = m.saveToFile(ctx); err != nil {
			m.removeTokenFamilyRecordCache(ctx, familyID)
			_, _ = gcache.Remove(ctx, DefaultPrefixAccess+accessInfo.TokenID)
			_, _ = m.removeTokenCache(ctx, accessToken)
			return nil, err
		}
	}
	return &TokenPair{
		AccessToken:      accessToken,
		AccessTokenInfo:  accessInfo,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

func (m *GToken) RefreshTokenPair(ctx context.Context, refreshToken string, expectedExtraData g.Map) (*TokenPair, error) {
	if !m.Init(ctx) || m.AutoRefreshToken || m.RefreshLimit != 1 {
		return nil, ErrRefreshTokenRejected
	}
	familyID, secret, err := parseRefreshCredential(refreshToken)
	if err != nil {
		return nil, ErrRefreshTokenRejected
	}
	digest := digestRefreshSecret(secret)
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		return m.refreshTokenPairCache(ctx, familyID, digest, expectedExtraData)
	default:
		return nil, ErrRefreshTokenRejected
	}
}

func (m *GToken) RevokeTokenFamily(ctx context.Context, accessToken string, refreshToken string) error {
	if !m.Init(ctx) {
		return nil
	}
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		return m.revokeTokenFamilyCache(ctx, accessToken, refreshToken)
	default:
		return ErrRefreshTokenRejected
	}
}

func refreshDigestMatches(encoded string, presented [sha256.Size]byte) bool {
	stored, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(stored) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(stored, presented[:]) == 1
}

func expectedExtraDataMatches(actual g.Map, expected g.Map) bool {
	for key, expectedValue := range expected {
		actualValue, ok := actual[key]
		if !ok || gconv.String(actualValue) != gconv.String(expectedValue) {
			return false
		}
	}
	return true
}
