package gtoken

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gogf/gf/v2/container/gvar"
	"github.com/gogf/gf/v2/frame/g"
)

func TestJSONNumberPrecision(t *testing.T) {
	const extra = `{"id":148817571809027123,"nested":[18446744073709551615,-9223372036854775808,1.234567890123456789,1e400],"flag":true,"text":"148817571809027123","empty":null}`
	for _, kind := range []string{"token", "family", "pair"} {
		for _, codec := range []string{"json", "outerUseNumber", "gvar"} {
			t.Run(kind+"/"+codec, func(t *testing.T) {
				var target any
				raw := `{"ExtraData":` + extra + `}`
				switch kind {
				case "token":
					target = &TokenInfo{}
				case "family":
					target = &TokenFamily{}
				case "pair":
					target = &TokenPair{}
					raw = `{"AccessTokenInfo":` + raw + `}`
				}
				var err error
				switch codec {
				case "json":
					err = json.Unmarshal([]byte(raw), target)
				case "outerUseNumber":
					decoder := json.NewDecoder(bytes.NewBufferString(raw))
					decoder.UseNumber()
					err = decoder.Decode(target)
				case "gvar":
					err = gvar.New(raw).Scan(target)
				}
				if err != nil {
					t.Fatal(err)
				}
				var data g.Map
				switch v := target.(type) {
				case *TokenInfo:
					data = v.ExtraData
				case *TokenFamily:
					data = v.ExtraData
				case *TokenPair:
					data = v.AccessTokenInfo.ExtraData
				}
				if n, ok := data["id"].(json.Number); !ok || n.String() != "148817571809027123" {
					t.Fatalf("id = %T(%v)", data["id"], data["id"])
				}
				nested := data["nested"].([]any)
				for i, want := range []string{"18446744073709551615", "-9223372036854775808", "1.234567890123456789", "1e400"} {
					if n, ok := nested[i].(json.Number); !ok || n.String() != want {
						t.Errorf("nested[%d] = %T(%v)", i, nested[i], nested[i])
					}
				}
				if data["flag"] != true || data["text"] != "148817571809027123" || data["empty"] != nil {
					t.Fatalf("non-number values changed: %v", data)
				}
			})
		}
	}
}

func TestStoredNumberPrecision(t *testing.T) {
	for _, mode := range []uint8{CacheModeCache, CacheModeRedis, CacheModeFile} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			ctx := t.Context()
			clearGlobalCache(t, ctx)
			t.Cleanup(func() { clearGlobalCache(t, ctx) })
			if mode == CacheModeRedis {
				useTestRedis(t)
			}
			clock := &testClock{now: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
			path := t.TempDir() + "/tokens.json"
			m := newPairTestGToken(clock, mode, path)
			const id = int64(148817571809027123)
			pair, err := m.NewTokenPair(ctx, "precision-user", g.Map{"tenantID": id, "nested": g.Map{"id": uint64(18446744073709551615), "exponent": json.Number("1e400")}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == CacheModeFile {
				clearGlobalCache(t, ctx)
				m = newPairTestGToken(clock, mode, path)
				m.Init(ctx)
			}
			check := func(data g.Map) {
				t.Helper()
				if fmt.Sprint(data["tenantID"]) != "148817571809027123" {
					t.Errorf("tenantID = %T(%v)", data["tenantID"], data["tenantID"])
				}
				nested := data["nested"].(map[string]any)
				if fmt.Sprint(nested["exponent"]) != "1e400" {
					t.Errorf("exponent = %v", nested["exponent"])
				}
				if fmt.Sprint(nested["id"]) != "18446744073709551615" {
					t.Errorf("nested id = %v", nested["id"])
				}
			}
			info, err := m.ValidateToken(ctx, pair.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			check(info.ExtraData)
			for _, wrong := range []any{id + 1, "148817571809027124"} {
				if _, err = m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": wrong}); !errors.Is(err, ErrRefreshTokenRejected) {
					t.Fatalf("adjacent tenant accepted: %v", err)
				}
			}
			renewed, err := m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": id})
			if err != nil {
				t.Fatal(err)
			}
			check(renewed.AccessTokenInfo.ExtraData)
			if _, err = m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": id + 1}); !errors.Is(err, ErrRefreshTokenRejected) {
				t.Fatalf("wrong tenant replay: %v", err)
			}
			if _, err = m.ValidateToken(ctx, renewed.AccessToken); err != nil {
				t.Fatalf("wrong tenant revoked successor: %v", err)
			}
			if _, err = m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": id}); !errors.Is(err, ErrRefreshTokenReplay) {
				t.Fatalf("replay: %v", err)
			}
			family, err := m.getTokenFamily(ctx, info.FamilyID)
			if err != nil {
				t.Fatal(err)
			}
			check(family.ExtraData)
			if _, err = m.ValidateToken(ctx, renewed.AccessToken); err == nil {
				t.Fatal("replay left successor valid")
			}
			other, err := m.NewTokenPair(ctx, "precision-revoke", g.Map{"tenantID": id, "nested": g.Map{"id": uint64(18446744073709551615), "exponent": json.Number("1e400")}})
			if err != nil {
				t.Fatal(err)
			}
			if err = m.RevokeTokenFamily(ctx, "", other.RefreshToken); err != nil {
				t.Fatal(err)
			}
			family, err = m.getTokenFamily(ctx, other.AccessTokenInfo.FamilyID)
			if err != nil {
				t.Fatal(err)
			}
			check(family.ExtraData)
		})
	}
}
