package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	"github.com/ulixes-bloom/ya-gophkeeper/pkg/security"
)

// SecretService handles operations related to secrets management.
type SecretService struct {
	db         domain.SecretRepository       // Database reposiory for user secret data persistence.
	objStorage domain.SecretObjectRepository // Object storage for handling secret files.
	rootKey    []byte                        // Encryption root key for secrets encryption.
}

// NewSecretService creates a new instance of SecretService.
func NewSecretService(db domain.SecretRepository, objStorage domain.SecretObjectRepository, rootKey []byte) *SecretService {
	return &SecretService{
		db:         db,
		objStorage: objStorage,
		rootKey:    rootKey,
	}
}

// CreateSecret stores a new secret.
func (s *SecretService) CreateSecret(ctx context.Context, secret *domain.Secret, contentReader io.Reader) error {
	dbSecret, err := s.db.GetLatestSecretByName(ctx, secret.UserID, secret.Name)
	if err != nil && !errors.Is(err, domain.ErrSecretNotFound) {
		return fmt.Errorf("application.CreateSecret: %w", err)
	}
	if dbSecret != nil {
		secret.Version = dbSecret.Version + 1
	} else {
		secret.Version = 1
	}

	aesEncryptingReader, err := security.NewAESEncryptingReader(contentReader, s.rootKey)
	if err != nil {
		return fmt.Errorf("application.CreateSecret: %w", err)
	}

	switch secret.Type {
	case domain.CredentialsSecret, domain.PaymentCardSecret:
		return s.createDataSecret(ctx, secret, aesEncryptingReader)
	case domain.FileSecret, domain.TextSecret:
		return s.createFileSecret(ctx, secret, aesEncryptingReader)
	default:
		return fmt.Errorf("application.CreateSecret: %w", domain.ErrInvalidSecretType)
	}
}

// createDataSecret function to create data-type secrets (e.g., CredentialsSecret, PaymentCardSecret)
func (s *SecretService) createDataSecret(ctx context.Context, secret *domain.Secret, aesEncryptingReader io.Reader) error {
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, aesEncryptingReader)
	if err != nil {
		return fmt.Errorf("application.createDataSecret: %w", err)
	}
	secret.Data = buf.Bytes()

	if err := s.db.CreateSecret(ctx, secret); err != nil {
		return fmt.Errorf("application.createDataSecret: %w", err)
	}

	return nil
}

// createFileSecret is a helper function to create file-type secrets (e.g., FileSecret, TextSecret)
func (s *SecretService) createFileSecret(ctx context.Context, secret *domain.Secret, aesEncryptingReader io.Reader) error {
	err := s.objStorage.SaveFileInChunks(ctx, generateSecretFilePath(secret), aesEncryptingReader)
	if err != nil {
		return fmt.Errorf("application.createFileSecret: %w", err)
	}

	if err := s.db.CreateSecret(ctx, secret); err != nil {
		deleteErr := s.objStorage.DeleteFile(ctx, fmt.Sprint(secret.Name, secret.Version))
		if deleteErr != nil {
			return fmt.Errorf("application.createFileSecret: failed to delete file after db error: %w", deleteErr)
		}
		return fmt.Errorf("application.createFileSecret: %w", err)
	}

	return nil
}

// GetSecretsList retrieves the list of secret names for a given user.
func (s *SecretService) GetSecretsList(ctx context.Context, userID string) ([]string, error) {
	secrets, err := s.db.GetSecretsList(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("application.GetSecretsList: %w", err)
	}

	return secrets, nil
}

// GetLatestSecretByName retrieves and decrypts the latest version of a secret.
func (s *SecretService) GetLatestSecretByName(ctx context.Context, userID, secretName string) (*domain.Secret, error) {
	secret, err := s.db.GetLatestSecretByName(ctx, userID, secretName)
	if err != nil {
		return nil, fmt.Errorf("application.GetLatestSecretByName: %w", err)
	}

	if err := s.decryptAndSetContent(secret); err != nil {
		return nil, fmt.Errorf("application.GetLatestSecretByName: %w", err)
	}

	return secret, nil
}

// GetSecretByVersion retrieves a specific version of a secret.
func (s *SecretService) GetSecretByVersion(ctx context.Context, userID, secretName string, version int32) (*domain.Secret, error) {
	if exists, err := s.db.IsSecretExist(ctx, userID, secretName); !exists {
		if err != nil {
			return nil, fmt.Errorf("application.GetSecretByVersion: %w", err)
		}
		return nil, domain.ErrSecretNotFound
	}

	secret, err := s.db.GetSecretByVersion(ctx, userID, secretName, version)
	if err != nil {
		return nil, fmt.Errorf("application.GetSecretByVersion: %w", err)
	}

	if err := s.decryptAndSetContent(secret); err != nil {
		return nil, fmt.Errorf("application.GetSecretByVersion: %w", err)
	}

	return secret, nil
}

// decryptAndSetContent handles decrypting the content of the secret and setting it.
func (s *SecretService) decryptAndSetContent(secret *domain.Secret) error {
	decryptedContent, err := security.DecryptAES(secret.Data, s.rootKey)
	if err != nil {
		return fmt.Errorf("application.decryptAndSetContent: %w", err)
	}
	secret.Data = decryptedContent
	return nil
}

// GetLatestSecretStreamByName retrieves the latest version of a secret as a stream.
func (s *SecretService) GetLatestSecretStreamByName(ctx context.Context, userID, secretName string) (*domain.Secret, io.ReadCloser, error) {
	secret, err := s.db.GetLatestSecretByName(ctx, userID, secretName)
	if err != nil {
		return nil, nil, fmt.Errorf("application.GetLatestSecretStreamByName: %w", err)
	}

	reader, err := s.objStorage.ReadFileInChunks(ctx, fmt.Sprintf("%s%d", secretName, secret.Version))
	if err != nil {
		return nil, nil, fmt.Errorf("application.GetLatestSecretStreamByName: %w", err)
	}

	decryptingReader, err := security.NewAESDecryptingReader(reader, s.rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("application.GetLatestSecretStreamByName: %w", err)
	}

	return secret, decryptingReader, nil
}

// GetSecretByVersion retrieves a specific version of a secret stream.
func (s *SecretService) GetSecretStreamByVersion(ctx context.Context, userID, secretName string, version int32) (*domain.Secret, io.ReadCloser, error) {
	if exists, err := s.db.IsSecretExist(ctx, userID, secretName); !exists {
		if err != nil {
			return nil, nil, fmt.Errorf("application.GetSecretStreamByVersion: %w", err)
		}
		return nil, nil, domain.ErrSecretNotFound
	}

	secret, err := s.db.GetSecretByVersion(ctx, userID, secretName, version)
	if err != nil {
		return nil, nil, fmt.Errorf("application.GetSecretStreamByVersion: %w", err)
	}

	reader, err := s.objStorage.ReadFileInChunks(ctx, fmt.Sprintf("%s%d", secretName, secret.Version))
	if err != nil {
		return nil, nil, fmt.Errorf("application.GetSecretStreamByVersion: %w", err)
	}

	decryptingReader, err := security.NewAESDecryptingReader(reader, s.rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("application.GetSecretStreamByVersion: %w", err)
	}

	return secret, decryptingReader, nil
}

// DeleteSecret removes a secret by name.
func (s *SecretService) DeleteSecret(ctx context.Context, userID, secretName string) error {
	secret, err := s.db.GetLatestSecretByName(ctx, userID, secretName)
	if err != nil {
		return fmt.Errorf("application.DeleteSecret: %w", err)
	}

	if secret.Type == domain.FileSecret || secret.Type == domain.TextSecret {
		for i := 1; i < int(secret.Version)+1; i++ {
			err = s.objStorage.DeleteFile(ctx, generateSecretFilePath(secret))
			if err != nil {
				return fmt.Errorf("application.DeleteSecret: %w", err)
			}
		}
	}

	if err = s.db.DeleteSecret(ctx, userID, secretName); err != nil {
		return fmt.Errorf("application.DeleteSecret: %w", err)
	}

	return nil
}

func generateSecretFilePath(secret *domain.Secret) string {
	return fmt.Sprintf("%s%d", secret.Name, secret.Version)
}
