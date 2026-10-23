Change Log
------------------------------
## 2026-10-23 v1.2.2
1. Preserve timezone offsets and subsecond precision in token, token-pair, family, and access-index JSON timestamps.
2. Read legacy v1.2 timezone-free timestamps as UTC and restore file-cache records through their JSON codecs.
3. Add Redis and file-restart regression coverage for expiry, renewal, and replay across UTC, Asia/Shanghai, and America/New_York.

## Unreleased v1.2.0
1. Add `NewTokenPair`, `RefreshTokenPair`, and `RevokeTokenFamily` for explicit one-time renewal.
2. Add replay-aware token families with absolute access/refresh expiry and successor revocation.
3. Add deterministic clock injection and Memory, File-restart, concurrency, and Redis Lua/CAS tests.
4. Preserve `NewToken`, `ValidateToken`, `RemoveToken`, and explicit legacy automatic-refresh behavior.
5. Mark `AutoRefreshToken` as deprecated for production use.
6. Require explicit opt-in for tests against an external Redis instance; the default Redis lifecycle suite uses isolated in-process miniredis.

## 2025-04-12 v1.0.0
A big refactor of github.com/goflyfox/gtoken. Almost rewrite it. Here are the changes:
1. In order to make login and logout api recognized by the OpenAPI module of GoFrame, I remove the login and logout func in original gtoken.
2. Now, you can write your own auth service and logic, but don't forget to use gtoken.NewToken() and gtoken.RemoveToken().  
3. Only group middleware is kept, since it's a recommended way in GoFrame to apply the standard router while using group.Bind() in it.
4. Breaking changes of the route authentication. Now /test and /test/ are recognized different and /test/* will not contain /test anymore. 
5. Cache is slightly modified by changing gredis ttl from seconds to milliseconds. A bug is fixed for initializing file cache.
6. Nearly remove all response json while only one left in the default handler of DoAfterAuth. You can rewrite this func by yourself.

## 2025-04-14 v1.1.0
1. To make it clear, use SingleSession instead of MultiLogin. If SingleSession is true, only one token can be kept for each user.
2. To apply SingleSession, the module of cache is rewritten. JWT tokens are treated as cache keys while another key user:{userId} is imported to record different sessions.
3. Do refactor for test.
4. It's worth to mention that AutoRefreshToken is still kept. If AutoRefreshToken is true, keep using a token, and its ttl will be refreshed automatically. Again, there must be a high risk for using this feature in non-local applications.
