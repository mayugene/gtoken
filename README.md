# gtoken

`gtoken` provides server-side bearer-token lifecycle management for GoFrame v2 applications. It supports Memory, Redis, and File cache modes, optional single-session behavior, explicit one-time renewal, and group-routing middleware.

## Go version

The minimum supported Go version is **1.25.0**, required by the current OpenTelemetry and `golang.org/x/sys` dependencies. The preferred development toolchain is **Go 1.27.3**, specified separately by the `toolchain` directive in `go.mod`.

To verify compatibility with the minimum version without automatically selecting the preferred toolchain, run:

```sh
GOTOOLCHAIN=go1.25.0 go test ./...
```

## Recommended lifecycle

For production applications, keep automatic sliding refresh disabled and use the explicit token-pair API:

```go
gt := &gtoken.GToken{
	CacheMode:        gtoken.CacheModeRedis,
	ExpireIn:         24 * time.Hour,
	RefreshExpireIn:  24 * time.Hour,
	RefreshLimit:     1,
	AutoRefreshToken: false,
}

pair, err := gt.NewTokenPair(ctx, userID, g.Map{"tenantID": tenantID})
if err != nil {
	return err
}
```

`pair.RefreshToken` is returned only on initial issue. It can be consumed once:

```go
renewed, err := gt.RefreshTokenPair(
	ctx,
	refreshToken,
	g.Map{"tenantID": tenantID},
)
```

The renewed pair contains a final access token and no refresh token. Reusing the original refresh token marks the family revoked and invalidates the successor access token.

Map `ErrRefreshTokenRejected`, `ErrRefreshTokenExpired`, and `ErrRefreshTokenReplay` to one generic public response. Detailed errors are for internal control flow and token-free security logging only.

Logout or administrative session termination uses:

```go
err := gt.RevokeTokenFamily(ctx, accessToken, refreshToken)
```

Either credential may identify the family. Invalid credentials are handled idempotently.

## Security rules

- Never log access tokens, refresh tokens, digests, or token-bearing URLs.
- Send bearer tokens only in the `Authorization` header.
- Bind refresh to stable expected extra data such as tenant or client identity.
- Use a frontend-wide single-flight refresh request; concurrent reuse is treated as replay.
- `AutoRefreshToken` is retained for compatibility but is deprecated for production because it creates an unlimited sliding session.
- File mode is for one process. Use Redis mode for atomic renewal across multiple application instances.
- Browser storage policy belongs to the application. Browser public clients that expose refresh tokens to JavaScript should follow OAuth refresh-token rotation guidance and use short absolute lifetimes.

## Cache modes

| Mode | Value | Intended use |
|---|---:|---|
| Memory | `0` | One process; tokens disappear on restart |
| Redis | `1` | Multi-instance production; Lua/CAS renewal |
| File | `2` | One process with restart persistence |

File mode restores unexpired access tokens, token families, access indexes, and consumed/revoked tombstones. It fails token issuance when persistence fails.

Token and family JSON timestamps use RFC3339Nano, including a timezone offset and subsecond precision. Legacy v1.2 timestamps in `YYYY-MM-DD HH:MM:SS` format are read as UTC, matching the clock used to issue them. Fractional seconds already lost in legacy records cannot be recovered.

JSON numbers in decoded `ExtraData` (including nested maps and arrays) are returned as `json.Number`, preserving large integer IDs and decimal precision. In-memory values supplied directly by callers may retain their original Go types. Callers should use an appropriate integer/decimal conversion instead of asserting `float64`; converting a large ID to `float64` loses precision. Refresh matching continues to accept equivalent integer and string IDs, while distinguishing adjacent large IDs.

Redis renewal and revocation validate records in Go and atomically compare the original JSON snapshot before writing Go-encoded payloads. Existing record formats remain readable. Accurate, unexpired and unrevoked legacy records retain their IDs; values already rounded and persisted by earlier versions cannot be recovered.

## Legacy API compatibility

`NewToken`, `ValidateToken`, and `RemoveToken` remain available. Existing callers that explicitly set `AutoRefreshToken: true` retain the previous sliding behavior. New production integrations should use the explicit pair API instead.

## Middleware

```go
server.Group("/", func(group *ghttp.RouterGroup) {
	if err := gt.UseMiddleware(ctx, group); err != nil {
		panic(err)
	}
	group.GET("/user", handler)
})
```

Public paths support exact and REST-style entries such as `POST:/login` and `/public/*`. A custom `DoAfterAuth` can map token data into the GoFrame request context and format unauthorized responses.

See `example/` for explicit login, one-time refresh, logout, and middleware usage.
