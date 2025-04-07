package domain

import (
	"context"
	"errors"
)

// User represents an entity with information for user authentication.
type User struct {
	ID           string // Unique identifier for the user
	Login        string // Login (username) of the user
	PasswordHash string // Hashed password of the user
}

var (
	ErrLoginExists        = errors.New("login already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrEmptyLogin         = errors.New("user login not provided")
	ErrEmptyPassword      = errors.New("user password not provided")
)

type (
	// AuthService defines the contract for authentication services.
	// This service is responsible for handling user login and registration logic.
	AuthService interface {
		Register(ctx context.Context, login, passswordHash string) (string, error)
		Login(ctx context.Context, login, passswordHash string) (string, error)
	}

	// UserRepository defines the contract for interacting with user-related data in a repository.
	// The repository is responsible for storing and retrieving user data.
	UserRepository interface {
		CreateUser(ctx context.Context, login, passswordHash string) (*User, error)
		FindUserByLogin(ctx context.Context, login string) (*User, error)
	}
)
