package gtoken

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func newPairTestGToken(clock *testClock, mode uint8, filePath string) *GToken {
	return &GToken{
		CacheMode:       mode,
		ExpireIn:        24 * time.Hour,
		RefreshExpireIn: 24 * time.Hour,
		RefreshLimit:    1,
		Clock:           clock.Now,
		CacheFilePath:   filePath,
	}
}

func TestRefreshCredentialRoundTrip(t *testing.T) {
	raw, digest, err := newRefreshCredential("family-1")
	if err != nil {
		t.Fatal(err)
	}

	familyID, secret, err := parseRefreshCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	if familyID != "family-1" {
		t.Fatalf("family id = %q, want family-1", familyID)
	}
	if len(secret) != refreshSecretBytes {
		t.Fatalf("secret bytes = %d, want %d", len(secret), refreshSecretBytes)
	}

	got := digestRefreshSecret(secret)
	if subtle.ConstantTimeCompare(got[:], digest[:]) != 1 {
		t.Fatal("refresh digest mismatch")
	}
}

func TestNewTokenUsesInjectedClock(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	m := &GToken{
		ExpireIn: 24 * time.Hour,
		Clock:    func() time.Time { return start },
	}
	m.Init(ctx)

	_, info, err := m.NewToken(ctx, "user-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := start.Add(24 * time.Hour); !info.ExpireAt.Time.Equal(want) {
		t.Fatalf("expire at = %s, want %s", info.ExpireAt, want)
	}
	if want := start.Add(12 * time.Hour); !info.RefreshAt.Time.Equal(want) {
		t.Fatalf("refresh at = %s, want %s", info.RefreshAt, want)
	}
}

func TestInitSetsRefreshDefaults(t *testing.T) {
	m := &GToken{}
	m.Init(context.Background())
	if m.RefreshExpireIn != DefaultRefreshExpireIn {
		t.Fatalf("refresh expire in = %s, want %s", m.RefreshExpireIn, DefaultRefreshExpireIn)
	}
	if m.RefreshLimit != DefaultRefreshLimit {
		t.Fatalf("refresh limit = %d, want %d", m.RefreshLimit, DefaultRefreshLimit)
	}
}

func TestNowUsesInjectedClock(t *testing.T) {
	want := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	m := &GToken{Clock: func() time.Time { return want }}
	if got := m.now(); !got.Equal(want) {
		t.Fatalf("now = %s, want %s", got, want)
	}
}

func TestParseRefreshCredentialRejectsMalformed(t *testing.T) {
	tests := []string{
		"",
		"missing-separator",
		".c2VjcmV0",
		"family.not-base64!",
		"family.c2hvcnQ",
		"family.a.b",
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, _, err := parseRefreshCredential(raw); err == nil {
				t.Fatalf("parseRefreshCredential(%q) unexpectedly succeeded", raw)
			}
		})
	}
}

func TestTokenPairLifecycle(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: start}
	m := newPairTestGToken(clock, CacheModeCache, "")

	pair, err := m.NewTokenPair(ctx, "user-1", g.Map{"tenantID": uint(7)})
	if err != nil {
		t.Fatal(err)
	}
	if want := start.Add(24 * time.Hour); !pair.AccessTokenInfo.ExpireAt.Time.Equal(want) {
		t.Fatalf("access expiry = %s, want %s", pair.AccessTokenInfo.ExpireAt, want)
	}
	if want := start.Add(24 * time.Hour); !pair.RefreshExpiresAt.Time.Equal(want) {
		t.Fatalf("refresh expiry = %s, want %s", pair.RefreshExpiresAt, want)
	}
	if _, err = m.ValidateToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("validate initial token: %v", err)
	}

	clock.Advance(23*time.Hour + 55*time.Minute)
	renewed, err := m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": uint(7)})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.RefreshToken != "" {
		t.Fatal("renewal returned a second refresh token")
	}
	if want := clock.Now().Add(24 * time.Hour); !renewed.AccessTokenInfo.ExpireAt.Time.Equal(want) {
		t.Fatalf("renewed expiry = %s, want %s", renewed.AccessTokenInfo.ExpireAt, want)
	}
	if _, err = m.ValidateToken(ctx, pair.AccessToken); err == nil {
		t.Fatal("initial access token remains valid after renewal")
	}
	if _, err = m.ValidateToken(ctx, renewed.AccessToken); err != nil {
		t.Fatalf("validate renewed token: %v", err)
	}

	if _, err = m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": uint(7)}); !errors.Is(err, ErrRefreshTokenReplay) {
		t.Fatalf("replay error = %v, want %v", err, ErrRefreshTokenReplay)
	}
	if _, err = m.ValidateToken(ctx, renewed.AccessToken); err == nil {
		t.Fatal("successor access token remains valid after replay")
	}
}

func TestRefreshExpectedExtraDataMismatchDoesNotConsume(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
	m := newPairTestGToken(clock, CacheModeCache, "")
	pair, err := m.NewTokenPair(ctx, "user-1", g.Map{"tenantID": uint(7)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": uint(8)}); !errors.Is(err, ErrRefreshTokenRejected) {
		t.Fatalf("mismatch error = %v", err)
	}
	if _, err = m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": uint(7)}); err != nil {
		t.Fatalf("valid refresh after mismatch: %v", err)
	}
}

func TestRefreshAtDeadlineIsRejected(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
	m := newPairTestGToken(clock, CacheModeCache, "")
	pair, err := m.NewTokenPair(ctx, "user-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(24 * time.Hour)
	if _, err = m.RefreshTokenPair(ctx, pair.RefreshToken, nil); !errors.Is(err, ErrRefreshTokenExpired) {
		t.Fatalf("deadline error = %v, want %v", err, ErrRefreshTokenExpired)
	}
	if _, err = m.ValidateToken(ctx, pair.AccessToken); err == nil {
		t.Fatal("access token remains valid at expiry")
	}
}

func TestRevokeTokenFamily(t *testing.T) {
	tests := []struct {
		name       string
		useAccess  bool
		useRefresh bool
	}{
		{name: "access only", useAccess: true},
		{name: "refresh only", useRefresh: true},
		{name: "both", useAccess: true, useRefresh: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			clock := &testClock{now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
			m := newPairTestGToken(clock, CacheModeCache, "")
			pair, err := m.NewTokenPair(ctx, "user-1", nil)
			if err != nil {
				t.Fatal(err)
			}
			var accessToken, refreshToken string
			if tt.useAccess {
				accessToken = pair.AccessToken
			}
			if tt.useRefresh {
				refreshToken = pair.RefreshToken
			}
			if err = m.RevokeTokenFamily(ctx, accessToken, refreshToken); err != nil {
				t.Fatal(err)
			}
			if err = m.RevokeTokenFamily(ctx, accessToken, refreshToken); err != nil {
				t.Fatalf("idempotent revoke: %v", err)
			}
			if _, err = m.ValidateToken(ctx, pair.AccessToken); err == nil {
				t.Fatal("access token remains valid after revoke")
			}
		})
	}
}

func TestRevokeTokenFamilyIgnoresForgedRefreshSecret(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
	m := newPairTestGToken(clock, CacheModeCache, "")
	pair, err := m.NewTokenPair(ctx, "user-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	familyID := strings.SplitN(pair.RefreshToken, ".", 2)[0]
	forged := familyID + "." + base64.RawURLEncoding.EncodeToString(make([]byte, refreshSecretBytes))
	if err = m.RevokeTokenFamily(ctx, "", forged); err != nil {
		t.Fatal(err)
	}
	if _, err = m.ValidateToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("forged refresh secret revoked access token: %v", err)
	}
}

func TestConcurrentRefreshRevokesReplayedFamily(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
	m := newPairTestGToken(clock, CacheModeCache, "")
	pair, err := m.NewTokenPair(ctx, "user-1", nil)
	if err != nil {
		t.Fatal(err)
	}

	const calls = 16
	start := make(chan struct{})
	results := make(chan *TokenPair, calls)
	errs := make(chan error, calls)
	var wg sync.WaitGroup
	for range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, refreshErr := m.RefreshTokenPair(ctx, pair.RefreshToken, nil)
			if refreshErr != nil {
				errs <- refreshErr
				return
			}
			results <- result
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)

	if len(results) != 1 {
		t.Fatalf("successful refreshes = %d, want 1", len(results))
	}
	winner := <-results
	if _, err = m.ValidateToken(ctx, winner.AccessToken); err == nil {
		t.Fatal("concurrent replay did not revoke winner")
	}
	for refreshErr := range errs {
		if !errors.Is(refreshErr, ErrRefreshTokenReplay) {
			t.Fatalf("concurrent error = %v", refreshErr)
		}
	}
}

func TestFileTokenFamilyRestartPreservesReplayState(t *testing.T) {
	ctx := context.Background()
	clearGlobalCache(t, ctx)
	clock := &testClock{now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
	filePath := t.TempDir() + "/gtoken.dat"
	m := newPairTestGToken(clock, CacheModeFile, filePath)
	m.Init(ctx)
	pair, err := m.NewTokenPair(ctx, "user-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := m.RefreshTokenPair(ctx, pair.RefreshToken, nil)
	if err != nil {
		t.Fatal(err)
	}

	clearGlobalCache(t, ctx)
	restarted := newPairTestGToken(clock, CacheModeFile, filePath)
	restarted.Init(ctx)
	if _, err = restarted.RefreshTokenPair(ctx, pair.RefreshToken, nil); !errors.Is(err, ErrRefreshTokenReplay) {
		t.Fatalf("restart replay error = %v", err)
	}
	if _, err = restarted.ValidateToken(ctx, renewed.AccessToken); err == nil {
		t.Fatal("restarted replay did not revoke successor")
	}
}

func TestFileTokenPairFailsClosedWhenPersistenceFails(t *testing.T) {
	ctx := context.Background()
	clearGlobalCache(t, ctx)
	clock := &testClock{now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
	m := newPairTestGToken(clock, CacheModeFile, t.TempDir())
	if pair, err := m.NewTokenPair(ctx, "user-1", nil); err == nil || pair != nil {
		t.Fatal("file persistence failure returned a token pair")
	}
}

func TestLegacyTokenDoesNotSlideWhenAutoRefreshDisabled(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: start}
	m := &GToken{ExpireIn: time.Hour, AutoRefreshToken: false, Clock: clock.Now}
	token, info, err := m.NewToken(ctx, "legacy-user", nil)
	if err != nil {
		t.Fatal(err)
	}
	wantExpiry := start.Add(time.Hour)
	clock.Advance(45 * time.Minute)
	validated, err := m.ValidateToken(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if !validated.ExpireAt.Time.Equal(wantExpiry) || !info.ExpireAt.Time.Equal(wantExpiry) {
		t.Fatalf("disabled auto refresh changed expiry to %s", validated.ExpireAt)
	}
	clock.Advance(15 * time.Minute)
	if _, err = m.ValidateToken(ctx, token); err == nil {
		t.Fatal("legacy token remains valid at expiry")
	}
}

func TestLegacyAutoRefreshRemainsCompatible(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: start}
	m := &GToken{ExpireIn: time.Hour, AutoRefreshToken: true, Clock: clock.Now}
	token, _, err := m.NewToken(ctx, "legacy-user", nil)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(31 * time.Minute)
	validated, err := m.ValidateToken(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if want := clock.Now().Add(time.Hour); !validated.ExpireAt.Time.Equal(want) {
		t.Fatalf("auto refresh expiry = %s, want %s", validated.ExpireAt, want)
	}
}

func clearGlobalCache(t *testing.T, ctx context.Context) {
	t.Helper()
	data, err := gcache.Data(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]any, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	if len(keys) > 0 {
		if err = gcache.Removes(ctx, keys); err != nil {
			t.Fatal(err)
		}
	}
}
