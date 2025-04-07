package security

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

// Claims struct defines the custom claims used in the JWT token, embedding the RegisteredClaims from the jwt package.
type Claims struct {
	jwt.RegisteredClaims
	UserID string // Custom claim to store the user's ID
}

// BuildJWTToken generates a signed JWT token with a user ID, a secret key, and a token lifetime.
func BuildJWTToken(userID string, secretKey string, tokenLifetime time.Duration) (string, error) {
	// Validate the userID is not empty
	if userID == "" {
		return "", fmt.Errorf("security.BuildJWTToken: userID cannot be empty")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenLifetime)),
		},
		UserID: userID,
	})

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("security.BuildJWTToken: failed to sign JWT token: %w", err)
	}

	return tokenString, nil
}

// GetUserID parses a JWT token and extracts the user ID from it using the provided secret key.
func GetUserID(tokenString, secretKey string) (string, error) {
	var claims Claims

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		log.Error().Msg(err.Error())
		return "", fmt.Errorf("security.GetUserID: failed to parse JWT token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("security.GetUserID: token is not valid")
	}

	return claims.UserID, nil
}
