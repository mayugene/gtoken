package model

type AuthLoginInput struct {
	Username string `json:"username" dc:"username" v:"required"`
	Password string `json:"password" dc:"password" v:"required"`
}

type AuthLoginOutput struct {
	TokenType string `json:"tokenType" dc:"Token type, default is Bearer"`
	Token     string `json:"token" dc:"Token string"`
	ExpireIn  int64  `json:"expireIn" dc:"expires in seconds"`
	Username  string `json:"username" dc:"username"`
}
