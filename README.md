This repo is based on the great work of https://github.com/goflyfox/gtoken. It offers a simple way for golang beginners to use [GoFrame](https://github.com/gogf/gf).

## Features
1. Use jwt.
2. Support cache/redis/file to store tokens.
3. Support refresh jwt automatically.
4. Support GoFrame v2.*. Currently, it's 2.9.0.
5. Work as a group routing middleware(best practise of GoFrame).
6. NanoId is used to reduce token bytes.

## Documents
1. Cache mode
    - Cache: 0
    - Redis: 1
    - File: 2
2. Choose to refresh token automatically by setting AutoRefreshToken true
3. Handle public paths(non-auth parts)
   - Public paths can be defined simply as []string{"/validation-code", "/activation"}
   - Restful formats like "POST:/activation" are also supported.
   - It's OK to add "/login" in PublicPaths or use a seperated group to bind the controller contains "/login". 
4. Initialize
   - UseMiddleware will automatically apply Init()
   - Init() is exposed basically for testing purpose
5. Add extra info
   - The default DoAfterAuth func can set the given g.Map into context.
   - If a self-defined DoAfterAuth is given, use the following code.
   ```
   for k, v := range data {
        r.SetCtxVar(k, v)
    }
   ```
6. Response format
   - gtoken is designed to avoid writing response directly.
   - A custom response can be applied by defining a new DoAfterAuth.
7. Token length
   - NanoId is used so that the token id length can be customized
   - Please refer to: https://zelark.github.io/nano-id-cc/ for more information about NanoId collision.
8. Refer to gtoken.GToken to get more parameter details

## Usage
```
   gToken := &gtoken.GToken{
      PublicPaths:      []string{"POST:/login", "/logout"},
      ExpireIn:         1 * time.Hour,
   }
   s.Group("/", func(group *ghttp.RouterGroup) {
      err := gToken.UseMiddleware(ctx, group)
      if err != nil {
        panic(err)
      }
      group.GET("/user", func(r *ghttp.Request) {
        r.Response.WriteJson(gtoken.DefaultResponse{Msg: "get user success"})
      })
   })
```