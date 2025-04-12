package gtoken_test

import (
	"context"
	_ "github.com/gogf/gf/contrib/nosql/redis/v2"
	"github.com/gogf/gf/v2/database/gredis"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/mayugene/gtoken/gtoken"
	"testing"
)

var userKey = "123123"

func TestEncryptDecryptToken(t *testing.T) {
	t.Log("test: encrypt and decrypt token")
	ctx := context.Background()

	t.Run("test gcache", func(t *testing.T) {
		t.Log("use cache mode: gcache")
		gToken := &gtoken.GToken{}
		gToken.Init(ctx)
		testEncryptDecrypt(t, ctx, gToken)
	})

	t.Run("test file cache", func(t *testing.T) {
		t.Log("use cache mode: file")
		gToken := &gtoken.GToken{CacheMode: gtoken.CacheModeFile}
		gToken.Init(ctx)
		testEncryptDecrypt(t, ctx, gToken)
	})

	t.Run("test redis cache", func(t *testing.T) {
		t.Log("use cache mode: redis")
		// Although it is convenient to use g.Redis()
		// But don't forget to import _ "github.com/gogf/gf/contrib/nosql/redis/v2", or it will panic
		redisConfig := gredis.Config{
			Address: "127.0.0.1:6379",
			Db:      1,
			Pass:    "",
		}
		gredis.SetConfig(&redisConfig)
		gToken := &gtoken.GToken{CacheMode: gtoken.CacheModeRedis}
		gToken.Init(ctx)
		_, err := g.Redis().DBSize(ctx)
		if err != nil {
			t.Error("test redis failed: cannot connect to redis server")
		} else {
			testEncryptDecrypt(t, ctx, gToken)
		}
	})
}

func BenchmarkEncryptDecryptToken(b *testing.B) {
	b.Log("benchmark: encrypt and decrypt token")

	ctx := context.Background()
	gToken := gtoken.GToken{}
	gToken.Init(ctx)

	newToken, err := gToken.NewToken(ctx, userKey, nil)
	if err != nil {
		b.Error(err)
	}
	validateToken, err := gToken.ValidateToken(ctx, newToken.Token)
	if err != nil {
		b.Error(err)
	}
	if validateToken.UserKey != userKey {
		b.Error(validateToken.UserKey)
	}
}

func testEncryptDecrypt(t *testing.T, ctx context.Context, gToken *gtoken.GToken) {
	t.Log("1. encrypt token")
	newToken, err := gToken.NewToken(ctx, userKey, nil)
	if err != nil {
		t.Error(err)
	}
	t.Log("2. validate token")
	validateToken, err := gToken.ValidateToken(ctx, newToken.Token)
	if err != nil {
		t.Error(err)
	}
	if validateToken.UserKey != userKey {
		t.Error(validateToken.UserKey)
	}
	t.Log("3. remove token and validate token again")
	ok, err := gToken.RemoveToken(ctx, newToken.Token)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("remove token failed")
	}
	validateToken1, _ := gToken.ValidateToken(ctx, newToken.Token)
	if validateToken1 != nil {
		t.Error("token is not removed")
	} else {
		t.Log("token has been removed correctly")
	}
}
