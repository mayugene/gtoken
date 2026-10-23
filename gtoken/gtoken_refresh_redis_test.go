package gtoken

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	_ "github.com/gogf/gf/contrib/nosql/redis/v2"
	"github.com/gogf/gf/v2/frame/g"
)

func TestRedisRefreshResultMapping(t *testing.T) {
	tests := []struct {
		code int
		want error
	}{
		{code: redisRefreshRejected, want: ErrRefreshTokenRejected},
		{code: redisRefreshExpired, want: ErrRefreshTokenExpired},
		{code: redisRefreshReplay, want: ErrRefreshTokenReplay},
	}
	for _, tt := range tests {
		if err := redisRefreshError(tt.code); !errors.Is(err, tt.want) {
			t.Fatalf("code %d error = %v, want %v", tt.code, err, tt.want)
		}
	}
}

func TestRedisTokenFamily(t *testing.T) {
	useTestRedis(t)
	ctx := context.Background()
	if _, err := g.Redis().DBSize(ctx); err != nil {
		t.Fatalf("connect isolated Redis: %v", err)
	}

	clock := &testClock{now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
	m := newPairTestGToken(clock, CacheModeRedis, "")
	pair, err := m.NewTokenPair(ctx, "redis-user-main", g.Map{"tenantID": uint(7)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.RevokeTokenFamily(ctx, pair.AccessToken, pair.RefreshToken) })

	if _, err = m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": uint(8)}); !errors.Is(err, ErrRefreshTokenRejected) {
		t.Fatalf("Redis mismatch error = %v", err)
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
			result, refreshErr := m.RefreshTokenPair(ctx, pair.RefreshToken, g.Map{"tenantID": uint(7)})
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
		t.Fatalf("Redis successful refreshes = %d, want 1", len(results))
	}
	winner := <-results
	if _, err = m.ValidateToken(ctx, winner.AccessToken); err == nil {
		t.Fatal("Redis concurrent replay did not revoke successor")
	}
	for refreshErr := range errs {
		if !errors.Is(refreshErr, ErrRefreshTokenReplay) {
			t.Fatalf("Redis concurrent error = %v", refreshErr)
		}
	}

	expiring, err := m.NewTokenPair(ctx, "redis-user-expiry", nil)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(24 * time.Hour)
	if _, err = m.RefreshTokenPair(ctx, expiring.RefreshToken, nil); !errors.Is(err, ErrRefreshTokenExpired) {
		t.Fatalf("Redis deadline error = %v", err)
	}

	revoked, err := m.NewTokenPair(ctx, "redis-user-revoke", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.RevokeTokenFamily(ctx, "", revoked.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err = m.ValidateToken(ctx, revoked.AccessToken); err == nil {
		t.Fatal("Redis revoke left access token valid")
	}
}
