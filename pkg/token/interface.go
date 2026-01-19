package token

// TokenPair contains the access and refresh tokens
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	AccessUUID   string
	RefreshUUID  string
	AtExpires    int64
	RtExpires    int64
}

// Claims defines the JWT claims (User)
type Claims struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email"`
	Role    string `json:"role"`
	TokenID string `json:"token_id"`
}

// Provider defines the interface for token operations
type Provider interface {
	GenerateTokenPair(userID, email, role string) (*TokenPair, error)
	ParseToken(tokenString string) (*Claims, error)
	ParseMapToken(tokenString string) (map[string]interface{}, error)
}
