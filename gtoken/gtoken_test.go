package gtoken_test

import (
	"context"
	_ "github.com/gogf/gf/contrib/nosql/redis/v2"
	"github.com/gogf/gf/v2/database/gredis"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/mayugene/gtoken/gtoken"
	"testing"
)

var (
	userId       = "ab3cl2"
	redisAddress = "127.0.0.1:6379"
)

func TestEncryptDecryptToken(t *testing.T) {
	t.Log("test: encrypt and decrypt token")
	ctx := context.Background()

	t.Run("test gcache", func(t *testing.T) {
		t.Log("use cache mode: gcache")
		gToken := &gtoken.GToken{}
		gToken.Init(ctx)
		testEncryptDecrypt(t, ctx, gToken)
		testExtraData(t, ctx, gToken)
	})

	t.Run("test file cache", func(t *testing.T) {
		t.Log("use cache mode: file")
		gToken := &gtoken.GToken{CacheMode: gtoken.CacheModeFile}
		gToken.Init(ctx)
		testEncryptDecrypt(t, ctx, gToken)
		testExtraData(t, ctx, gToken)
	})

	t.Run("test redis cache", func(t *testing.T) {
		t.Log("use cache mode: redis")
		// Although it is convenient to use g.Redis()
		// But don't forget to import _ "github.com/gogf/gf/contrib/nosql/redis/v2", or it will panic
		redisConfig := gredis.Config{
			Address: redisAddress,
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
			testExtraData(t, ctx, gToken)
		}
	})
}

func BenchmarkEncryptDecryptToken(b *testing.B) {
	b.Log("benchmark: encrypt and decrypt token")

	ctx := context.Background()
	gToken := gtoken.GToken{}
	gToken.Init(ctx)

	newToken, _, err := gToken.NewToken(ctx, userId, nil)
	if err != nil {
		b.Error(err)
	}
	validatedInfo, err := gToken.ValidateToken(ctx, newToken)
	if err != nil {
		b.Error(err)
	}
	if validatedInfo.UserID != userId {
		b.Error("validate token failed")
	}
}

func testEncryptDecrypt(t *testing.T, ctx context.Context, gToken *gtoken.GToken) {
	t.Log("1. encrypt token")
	newToken, _, err := gToken.NewToken(ctx, userId, nil)
	if err != nil {
		t.Error(err)
	}
	t.Log("2. validate token")
	validatedInfo, err := gToken.ValidateToken(ctx, newToken)
	if err != nil {
		t.Error(err)
	}
	if validatedInfo.UserID != userId {
		t.Error("validate token failed")
	}
	t.Log("3. remove token and validate token again")
	ok, err := gToken.RemoveToken(ctx, newToken)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("remove token failed")
	}
	validateInfo1, _ := gToken.ValidateToken(ctx, newToken)
	if validateInfo1 != nil {
		t.Error("token is not removed")
	} else {
		t.Log("token has been removed correctly")
	}
}

func testExtraData(t *testing.T, ctx context.Context, gToken *gtoken.GToken) {
	t.Log("1. encrypt token with extra data")
	testUsername := "John Doe"
	testRole := "super-admin"
	newToken, _, err := gToken.NewToken(ctx, userId, g.Map{"username": testUsername, "role": testRole})
	if err != nil {
		t.Error(err)
	}
	t.Log("2. validate token with extra data")
	validatedInfo, err := gToken.ValidateToken(ctx, newToken)
	if err != nil {
		t.Error(err)
	}
	if validatedInfo.ExtraData["username"].(string) != testUsername || validatedInfo.ExtraData["role"].(string) != testRole {
		t.Error("validate token with extra data failed")
	}
	t.Log("3. remove token and validate token again")
	ok, err := gToken.RemoveToken(ctx, newToken)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("remove token failed")
	}
}
