package gtoken

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gogf/gf/v2/container/gvar"
	"github.com/gogf/gf/v2/database/gredis"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
)

func useLocalZone(t *testing.T, name string) {
	t.Helper()
	location, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	previous := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previous })
}

func TestTokenJSONTimes(t *testing.T) {
	useLocalZone(t, "Asia/Shanghai")
	want := time.Date(2026, 10, 23, 12, 0, 0, 123456789, time.FixedZone("offset", -5*3600))
	tests := []struct {
		name    string
		value   any
		decoded any
		fields  []string
	}{
		{"token", TokenInfo{UserID: "user", ExpireAt: gtime.New(want), RefreshAt: gtime.New(want)}, &TokenInfo{}, []string{"ExpireAt", "RefreshAt"}},
		{"family", TokenFamily{IssuedAt: gtime.New(want), RefreshExpiresAt: gtime.New(want), FamilyExpiresAt: gtime.New(want)}, &TokenFamily{}, []string{"issuedAt", "refreshExpiresAt", "familyExpiresAt"}},
		{"index", accessFamilyIndex{ExpireAt: gtime.New(want)}, &accessFamilyIndex{}, []string{"expireAt"}},
		{"pair", TokenPair{RefreshExpiresAt: gtime.New(want)}, &TokenPair{}, []string{"RefreshExpiresAt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := gjson.Encode(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			for _, field := range tt.fields {
				var raw string
				if err = json.Unmarshal(fields[field], &raw); err != nil {
					t.Fatal(err)
				}
				got, err := time.Parse(time.RFC3339Nano, raw)
				if err != nil || !got.Equal(want) {
					t.Errorf("%s = %q, want %s (parse error: %v)", field, raw, want.Format(time.RFC3339Nano), err)
				}
			}
			if err = gvar.New(string(data)).Scan(tt.decoded); err != nil {
				t.Fatal(err)
			}
			roundTrip, err := gjson.Encode(tt.decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, roundTrip) {
				t.Fatalf("JSON changed after decoding: %s => %s", data, roundTrip)
			}
		})
	}
}

func TestTokenJSONNullZeroAndInvalidTime(t *testing.T) {
	for _, raw := range []string{`{}`, `{"ExpireAt":null,"RefreshAt":null}`, `{"ExpireAt":"","RefreshAt":""}`, `{"ExpireAt":"0001-01-01T00:00:00Z"}`} {
		var info TokenInfo
		if err := json.Unmarshal([]byte(raw), &info); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		if !info.ExpireAt.IsZero() || !info.RefreshAt.IsZero() {
			t.Fatalf("nonzero timestamps for %s", raw)
		}
		if _, err := json.Marshal(info); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{`{"ExpireAt":"invalid"}`, `{"ExpireAt":42}`, `{"ExpireAt":"2026-99-99 12:00:00"}`} {
		var info TokenInfo
		if err := json.Unmarshal([]byte(raw), &info); err == nil {
			t.Fatalf("invalid timestamp accepted: %s", raw)
		}
	}
}

func TestLegacyTokenJSONTimesAreUTC(t *testing.T) {
	useLocalZone(t, "Asia/Shanghai")
	want := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var token TokenInfo
	if err := gvar.New(`{"userID":"old","ExpireAt":"2026-10-23 12:00:00","RefreshAt":"2026-10-23 12:00:00"}`).Scan(&token); err != nil {
		t.Fatal(err)
	}
	var family TokenFamily
	if err := gvar.New(`{"issuedAt":"2026-10-23 12:00:00","refreshExpiresAt":"2026-10-23 12:00:00","familyExpiresAt":"2026-10-23 12:00:00"}`).Scan(&family); err != nil {
		t.Fatal(err)
	}
	var index accessFamilyIndex
	if err := gvar.New(`{"expireAt":"2026-10-23 12:00:00"}`).Scan(&index); err != nil {
		t.Fatal(err)
	}
	for _, got := range []*gtime.Time{token.ExpireAt, token.RefreshAt, family.IssuedAt, family.RefreshExpiresAt, family.FamilyExpiresAt, index.ExpireAt} {
		if got == nil || !got.Time.Equal(want) {
			t.Errorf("decoded time = %v, want %s", got, want)
		}
	}
}

func TestStoredTokenTimezoneLifecycle(t *testing.T) {
	for _, zone := range []string{"UTC", "Asia/Shanghai", "America/New_York"} {
		t.Run(zone, func(t *testing.T) {
			useLocalZone(t, zone)
			for _, mode := range []uint8{CacheModeRedis, CacheModeFile} {
				for _, legacy := range []bool{false, true} {
					t.Run(timezoneCaseName(mode, legacy), func(t *testing.T) {
						ctx := t.Context()
						clearGlobalCache(t, ctx)
						t.Cleanup(func() { clearGlobalCache(t, ctx) })
						var server *miniredis.Miniredis
						if mode == CacheModeRedis {
							server = useTestRedis(t)
						}
						start := time.Date(2026, 10, 23, 12, 0, 0, 123456789, time.UTC)
						if legacy {
							start = start.Truncate(time.Second)
						}
						clock := &testClock{now: start}
						path := t.TempDir() + "/tokens.json"
						m := newPairTestGToken(clock, mode, path)
						pair, err := m.NewTokenPair(ctx, "timezone-user", nil)
						if err != nil {
							t.Fatal(err)
						}
						deadlinePair, err := m.NewTokenPair(ctx, "deadline-user", nil)
						if err != nil {
							t.Fatal(err)
						}
						if mode == CacheModeFile {
							if legacy {
								data, err := os.ReadFile(path)
								if err != nil {
									t.Fatal(err)
								}
								if err = os.WriteFile(path, legacyTimeJSON(t, data), 0600); err != nil {
									t.Fatal(err)
								}
							}
							clearGlobalCache(t, ctx)
							m = newPairTestGToken(clock, mode, path)
							m.Init(ctx)
						} else if legacy {
							server.Select(1)
							for _, key := range server.Keys() {
								if server.Type(key) != "string" {
									continue
								}
								data, err := server.Get(key)
								if err != nil {
									t.Fatal(err)
								}
								ttl := server.TTL(key)
								if err = server.Set(key, string(legacyTimeJSON(t, []byte(data)))); err != nil {
									t.Fatal(err)
								}
								server.SetTTL(key, ttl)
							}
						}
						info, err := m.ValidateToken(ctx, pair.AccessToken)
						if err != nil {
							t.Fatal(err)
						}
						if !info.ExpireAt.Time.Equal(start.Add(24*time.Hour)) || !info.RefreshAt.Time.Equal(start.Add(12*time.Hour)) {
							t.Fatalf("stored times changed: expiry=%s refresh=%s", info.ExpireAt.Time.Format(time.RFC3339Nano), info.RefreshAt.Time.Format(time.RFC3339Nano))
						}
						family, err := m.getTokenFamily(ctx, info.FamilyID)
						if err != nil {
							t.Fatal(err)
						}
						for _, times := range []struct {
							got  *gtime.Time
							want time.Time
						}{
							{family.IssuedAt, start}, {family.RefreshExpiresAt, start.Add(24 * time.Hour)}, {family.FamilyExpiresAt, start.Add(48 * time.Hour)},
						} {
							if times.got == nil || !times.got.Time.Equal(times.want) {
								t.Fatalf("family time = %v, want %s", times.got, times.want)
							}
						}
						clock.Advance(23 * time.Hour)
						if _, err = m.ValidateToken(ctx, pair.AccessToken); err != nil {
							t.Fatalf("access before deadline: %v", err)
						}
						renewed, err := m.RefreshTokenPair(ctx, pair.RefreshToken, nil)
						if err != nil {
							t.Fatalf("refresh before deadline: %v", err)
						}
						if _, err = m.ValidateToken(ctx, renewed.AccessToken); err != nil {
							t.Fatalf("validate successor: %v", err)
						}
						if _, err = m.RefreshTokenPair(ctx, pair.RefreshToken, nil); !errors.Is(err, ErrRefreshTokenReplay) {
							t.Fatalf("replay: %v", err)
						}
						if _, err = m.ValidateToken(ctx, renewed.AccessToken); err == nil {
							t.Fatal("replay did not revoke successor")
						}
						clock.Advance(time.Hour)
						if _, err = m.RefreshTokenPair(ctx, deadlinePair.RefreshToken, nil); !errors.Is(err, ErrRefreshTokenExpired) {
							t.Fatalf("refresh at deadline: %v", err)
						}
						if _, err = m.ValidateToken(ctx, deadlinePair.AccessToken); err == nil {
							t.Fatal("access accepted at deadline")
						}
					})
				}
			}
		})
	}
}

func useTestRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	server := miniredis.RunT(t)
	config := &gredis.Config{Address: server.Addr(), Db: 1}
	previousConfig, configured := gredis.GetConfig()
	gredis.SetConfig(config)
	client, err := gredis.New(config)
	if err != nil {
		t.Fatal(err)
	}
	shared := g.Redis()
	// Replace the command groups too: SetAdapter alone leaves them bound to
	// the previous adapter in GoFrame's cached default Redis client.
	previousClient := *shared
	*shared = *client
	t.Cleanup(func() {
		*shared = previousClient
		if configured {
			gredis.SetConfig(previousConfig)
		}
		_ = client.Close(t.Context())
	})
	return server
}

func timezoneCaseName(mode uint8, legacy bool) string {
	name := "redis"
	if mode == CacheModeFile {
		name = "file"
	}
	if legacy {
		name += "/legacy"
	} else {
		name += "/new"
	}
	return name
}

func legacyTimeJSON(t *testing.T, data []byte) []byte {
	t.Helper()
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	var convert func(any)
	convert = func(value any) {
		if fields, ok := value.(map[string]any); ok {
			for key, field := range fields {
				if raw, ok := field.(string); ok {
					if instant, err := time.Parse(time.RFC3339Nano, raw); err == nil {
						fields[key] = instant.UTC().Format("2006-01-02 15:04:05")
					}
				} else {
					convert(field)
				}
			}
		}
	}
	convert(value)
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
