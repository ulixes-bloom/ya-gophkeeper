package domain

import (
	"context"
	"errors"
	"io"
	"time"
)

// SecretType represents the type of secret
type SecretType string

// Define constant values for different types of secrets
const (
	CredentialsSecret SecretType = "credentials"
	PaymentCardSecret SecretType = "payment_card"
	FileSecret        SecretType = "file"
	TextSecret        SecretType = "text"
)

// Secret represents a single secret's information and data
type Secret struct {
	ID        string     // Unique identifier for the secret
	Name      string     // Name of the secret
	UserID    string     // User ID associated with the secret
	Type      SecretType // The type of secret (e.g., credentials, payment card, etc.)
	Data      []byte     // The actual secret data (e.g., encrypted password or card info)
	Metadata  string     // Additional metadata related to the secret (e.g., description or tags)
	Version   int32      // Version number of the secret (used for versioning the secret data)
	CreatedAt time.Time  // Timestamp of when the secret was created
}

var (
	ErrSecretNotFound           = errors.New("secret not found")
	ErrSecretVersionNotFound    = errors.New("secret version not found")
	ErrInvalidSecretType        = errors.New("invalid secret type")
	ErrEmptySecretInfo          = errors.New("secret info not provided")
	ErrEmptySecretName          = errors.New("secret name not provided")
	ErrNonPositiveSecretVersion = errors.New("secret version must be positive")
)

type (
	// SecretService defines the application layer interface for managing secrets.
	SecretService interface {
		CreateSecret(ctx context.Context, secret *Secret, contentReader io.Reader) error

		GetSecretsList(ctx context.Context, userID string) ([]string, error)
		GetLatestSecretByName(ctx context.Context, userID, secretName string) (*Secret, error)
		GetLatestSecretStreamByName(ctx context.Context, userID, secretName string) (*Secret, io.ReadCloser, error)
		GetSecretByVersion(ctx context.Context, userID, secretName string, version int32) (*Secret, error)
		GetSecretStreamByVersion(ctx context.Context, userID, secretName string, version int32) (*Secret, io.ReadCloser, error)

		DeleteSecret(ctx context.Context, userID, secretName string) error
	}

	// SecretRepository defines the data access layer interface for storing and retrieving secrets.
	SecretRepository interface {
		CreateSecret(ctx context.Context, secret *Secret) error

		IsSecretExist(ctx context.Context, userID, secretName string) (bool, error)
		GetSecretsList(ctx context.Context, userID string) ([]string, error)
		GetLatestSecretByName(ctx context.Context, userID, secretName string) (*Secret, error)
		GetSecretByVersion(ctx context.Context, userID, secretName string, version int32) (*Secret, error)

		DeleteSecret(ctx context.Context, userID, secretName string) error
	}

	// SecretObjectRepository defines the repository for handling file storage associated with secrets.
	SecretObjectRepository interface {
		SaveFileInChunks(ctx context.Context, objectName string, contentReader io.Reader) error
		ReadFileInChunks(ctx context.Context, objectName string) (io.ReadCloser, error)
		DeleteFile(ctx context.Context, objectName string) error
	}
)
