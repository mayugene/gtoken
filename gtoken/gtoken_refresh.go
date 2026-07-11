package gtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
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
