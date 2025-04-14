Change Log
------------------------------
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
