package application

import (
	"context"
	"fmt"
	"time"

	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	"github.com/ulixes-bloom/ya-gophkeeper/pkg/security"
)

// AuthService handles user authentication-related operations.
type AuthService struct {
	repo             domain.UserRepository // Database reposiory for user data persistence.
	jwtTokenBuildKey string                // Secret key used for JWT token generation.
	jwtTokenLifetime time.Duration         // JWT token expiration duration.
}

// NewAuthService creates a new instance of AuthService.
func NewAuthService(repo domain.UserRepository, jwtTokenBuildKey string, jwtTokenLifetime time.Duration) *AuthService {
	return &AuthService{
		repo:             repo,
		jwtTokenBuildKey: jwtTokenBuildKey,
		jwtTokenLifetime: jwtTokenLifetime,
	}
}

// Register creates a new user and returns a JWT token if successful.
func (s *AuthService) Register(ctx context.Context, login, password string) (string, error) {
	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("security.HashPassword: %w", err)
	}

	domainUser, err := s.repo.CreateUser(ctx, login, passwordHash)
	if err != nil {
		return "", fmt.Errorf("repo.CreateUser: %w", err)
	}

	token, err := security.BuildJWTToken(domainUser.ID, s.jwtTokenBuildKey, s.jwtTokenLifetime)
	if err != nil {
		return "", fmt.Errorf("security.BuildJWTToken: %w", err)
	}

	return token, nil
}

// Login authenticates user and returns a JWT token if successful.
func (s *AuthService) Login(ctx context.Context, login, password string) (string, error) {
	domainUser, err := s.repo.FindUserByLogin(ctx, login)
	if err != nil {
		return "", fmt.Errorf("repo.FindUserByLogin: %w", err)
	}

	if err := security.ValidatePasswordHash(password, domainUser.PasswordHash); err != nil {
		return "", fmt.Errorf("security.ValidatePasswordHash: %w", err)
	}

	token, err := security.BuildJWTToken(domainUser.ID, s.jwtTokenBuildKey, s.jwtTokenLifetime)
	if err != nil {
		return "", fmt.Errorf("security.BuildJWTToken: %w", err)
	}

	return token, nil
}
