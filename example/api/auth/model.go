package auth

type LoginInput struct {
	Username string `json:"username" dc:"username" v:"required"`
	Password string `json:"password" dc:"password" v:"required"`
}

type LoginOutput struct {
	TokenType string `json:"tokenType" dc:"Token type, default is Bearer"`
	Token     string `json:"token" dc:"Token string"`
	ExpireIn  int64  `json:"expireIn" dc:"expires in seconds"`
	Username  string `json:"username" dc:"username"`
}
