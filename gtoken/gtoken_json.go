package gtoken

import (
	"encoding/json"
	"time"

	"github.com/gogf/gf/v2/os/gtime"
)

// jsonTime uses time.Time's RFC3339Nano encoding instead of gtime's timezone-free
// encoding. Legacy v1.2 records were written in UTC, even on non-UTC hosts.
type jsonTime struct {
	time.Time
}

func (t *jsonTime) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value == "" {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		parsed, err = time.Parse("2006-01-02 15:04:05", value)
	}
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

func toJSONTime(value *gtime.Time) *jsonTime {
	if value == nil {
		return nil
	}
	return &jsonTime{Time: value.Time}
}

func fromJSONTime(value *jsonTime) *gtime.Time {
	if value == nil {
		return nil
	}
	return gtime.New(value.Time)
}

type tokenInfoAlias TokenInfo
type tokenInfoJSON struct {
	*tokenInfoAlias
	ExpireAt  *jsonTime `json:"ExpireAt"`
	RefreshAt *jsonTime `json:"RefreshAt"`
}

// MarshalJSON preserves expiry timezone and subsecond precision.
func (info TokenInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(tokenInfoJSON{(*tokenInfoAlias)(&info), toJSONTime(info.ExpireAt), toJSONTime(info.RefreshAt)})
}

// UnmarshalJSON also accepts legacy UTC timestamps without an explicit offset.
func (info *TokenInfo) UnmarshalJSON(data []byte) error {
	value := tokenInfoJSON{tokenInfoAlias: (*tokenInfoAlias)(info), ExpireAt: toJSONTime(info.ExpireAt), RefreshAt: toJSONTime(info.RefreshAt)}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	info.ExpireAt, info.RefreshAt = fromJSONTime(value.ExpireAt), fromJSONTime(value.RefreshAt)
	return nil
}

type tokenFamilyAlias TokenFamily
type tokenFamilyJSON struct {
	*tokenFamilyAlias
	IssuedAt         *jsonTime `json:"issuedAt"`
	RefreshExpiresAt *jsonTime `json:"refreshExpiresAt"`
	FamilyExpiresAt  *jsonTime `json:"familyExpiresAt"`
}

// MarshalJSON preserves lifecycle timestamps in persisted family records.
func (family TokenFamily) MarshalJSON() ([]byte, error) {
	return json.Marshal(tokenFamilyJSON{(*tokenFamilyAlias)(&family), toJSONTime(family.IssuedAt), toJSONTime(family.RefreshExpiresAt), toJSONTime(family.FamilyExpiresAt)})
}

// UnmarshalJSON also accepts legacy UTC timestamps without an explicit offset.
func (family *TokenFamily) UnmarshalJSON(data []byte) error {
	value := tokenFamilyJSON{tokenFamilyAlias: (*tokenFamilyAlias)(family), IssuedAt: toJSONTime(family.IssuedAt), RefreshExpiresAt: toJSONTime(family.RefreshExpiresAt), FamilyExpiresAt: toJSONTime(family.FamilyExpiresAt)}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	family.IssuedAt = fromJSONTime(value.IssuedAt)
	family.RefreshExpiresAt = fromJSONTime(value.RefreshExpiresAt)
	family.FamilyExpiresAt = fromJSONTime(value.FamilyExpiresAt)
	return nil
}

type accessFamilyIndexAlias accessFamilyIndex
type accessFamilyIndexJSON struct {
	*accessFamilyIndexAlias
	ExpireAt *jsonTime `json:"expireAt"`
}

func (index accessFamilyIndex) MarshalJSON() ([]byte, error) {
	return json.Marshal(accessFamilyIndexJSON{(*accessFamilyIndexAlias)(&index), toJSONTime(index.ExpireAt)})
}

func (index *accessFamilyIndex) UnmarshalJSON(data []byte) error {
	value := accessFamilyIndexJSON{accessFamilyIndexAlias: (*accessFamilyIndexAlias)(index), ExpireAt: toJSONTime(index.ExpireAt)}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	index.ExpireAt = fromJSONTime(value.ExpireAt)
	return nil
}

type tokenPairAlias TokenPair
type tokenPairJSON struct {
	*tokenPairAlias
	RefreshExpiresAt *jsonTime
}

// MarshalJSON preserves the refresh deadline returned to callers.
func (pair TokenPair) MarshalJSON() ([]byte, error) {
	return json.Marshal(tokenPairJSON{(*tokenPairAlias)(&pair), toJSONTime(pair.RefreshExpiresAt)})
}

// UnmarshalJSON also accepts legacy UTC timestamps without an explicit offset.
func (pair *TokenPair) UnmarshalJSON(data []byte) error {
	value := tokenPairJSON{tokenPairAlias: (*tokenPairAlias)(pair), RefreshExpiresAt: toJSONTime(pair.RefreshExpiresAt)}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	pair.RefreshExpiresAt = fromJSONTime(value.RefreshExpiresAt)
	return nil
}
