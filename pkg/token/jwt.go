package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// jwtClaims is an internal struct to satisfy jwt.Claims interface
type jwtClaims struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email"`
	Role    string `json:"role"`
	TokenID string `json:"token_id"`
	jwt.RegisteredClaims
}

// jwt.go implements the Provider interface using JWT

type jwtProvider struct {
	secret string
}

// NewJWTProvider creates a new instance of JWT provider
func NewJWTProvider(secret string) Provider {
	return &jwtProvider{
		secret: secret,
	}
}

// GenerateTokenPair generates new access and refresh tokens
func (p *jwtProvider) GenerateTokenPair(userID, email, role string) (*TokenPair, error) {
	td := &TokenPair{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUUID = uuid.New().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix() // Expires in 7 days
	td.RefreshUUID = uuid.New().String()

	// Access Token
	atClaims := &jwtClaims{
		UserID:  userID,
		Email:   email,
		Role:    role,
		TokenID: td.AccessUUID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(td.AtExpires, 0)),
			Issuer:    "stream.api",
		},
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	var err error
	td.AccessToken, err = at.SignedString([]byte(p.secret))
	if err != nil {
		return nil, err
	}

	// Refresh Token
	// Refresh token can just be a random string or a JWT.
	// Common practice: JWT for stateless verification, or Opaque string for stateful.
	// Here we use JWT so we can carry some metadata if needed, but we check Redis anyway.
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = userID
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(p.secret))
	if err != nil {
		return nil, err
	}

	return td, nil
}

// ParseToken parses the access token returning Claims
func (p *jwtProvider) ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(p.secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwtClaims); ok && token.Valid {
		return &Claims{
			UserID:  claims.UserID,
			Email:   claims.Email,
			Role:    claims.Role,
			TokenID: claims.TokenID,
		}, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// ParseMapToken parses token returning map[string]interface{} (generic)
func (p *jwtProvider) ParseMapToken(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(p.secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrTokenInvalidClaims
}
