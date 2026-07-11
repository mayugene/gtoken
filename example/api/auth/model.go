package auth

type LoginInput struct {
	Username string `json:"username" dc:"username" v:"required"`
	Password string `json:"password" dc:"password" v:"required"`
}

type LoginOutput struct {
	TokenType        string `json:"tokenType" dc:"Token type, default is Bearer"`
	Token            string `json:"token" dc:"Access token"`
	ExpireIn         int64  `json:"expireIn" dc:"Access token lifetime in seconds"`
	ExpiresAt        string `json:"expiresAt" dc:"Access token expiry in RFC3339"`
	RefreshToken     string `json:"refreshToken" dc:"One-time refresh token"`
	RefreshExpiresAt string `json:"refreshExpiresAt" dc:"Refresh expiry in RFC3339"`
	Refreshable      bool   `json:"refreshable" dc:"Whether one refresh remains"`
	Username         string `json:"username" dc:"username"`
}

type RefreshInput struct {
	RefreshToken string `json:"refreshToken" v:"required"`
}

type RefreshOutput struct {
	TokenType   string `json:"tokenType"`
	Token       string `json:"token"`
	ExpireIn    int64  `json:"expireIn"`
	ExpiresAt   string `json:"expiresAt"`
	Refreshable bool   `json:"refreshable"`
}

type LogoutInput struct {
	RefreshToken string `json:"refreshToken"`
}
