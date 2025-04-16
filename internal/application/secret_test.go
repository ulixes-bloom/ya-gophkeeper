package application_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/application"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/config"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/mocks"
)

func TestSecretService_CreateSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	conf := config.GetDefault()
	ctx := context.Background()

	mockSecretDBRepo := mocks.NewMockSecretRepository(ctrl)
	mockSecretObjRepo := mocks.NewMockSecretObjectRepository(ctrl)
	secretService := application.NewSecretService(mockSecretDBRepo, mockSecretObjRepo, []byte(conf.RootKey))

	tests := []struct {
		name          string
		secret        domain.Secret
		secretData    io.Reader
		mockSetup     func()
		expectedError error
	}{
		{
			name: "successfully create new credentials secret",
			secret: domain.Secret{
				UserID: "user1",
				Name:   "new-secret",
				Type:   domain.CredentialsSecret,
			},
			secretData: bytes.NewBufferString("secret-content"),
			mockSetup: func() {
				secret := &domain.Secret{
					UserID: "user1",
					Name:   "new-secret",
					Type:   domain.CredentialsSecret,
				}

				// Expect no existing secret
				mockSecretDBRepo.EXPECT().
					GetLatestSecretByName(ctx, secret.UserID, secret.Name).
					Return(nil, domain.ErrSecretNotFound)

				// Expect data secret to be created
				mockSecretDBRepo.EXPECT().
					CreateSecret(ctx, gomock.Any()).
					DoAndReturn(func(_ context.Context, s *domain.Secret) error {
						assert.Equal(t, "user1", s.UserID)
						assert.Equal(t, "new-secret", s.Name)
						assert.Equal(t, domain.CredentialsSecret, s.Type)
						assert.Equal(t, int32(1), s.Version)
						return nil
					})
			},
			expectedError: nil,
		},
		{
			name: "successfully create new version of existing secret",
			secret: domain.Secret{
				UserID: "user1",
				Name:   "existing-secret",
				Type:   domain.PaymentCardSecret,
			},
			secretData: bytes.NewBufferString("secret-content"),
			mockSetup: func() {
				secret := &domain.Secret{
					UserID: "user1",
					Name:   "existing-secret",
					Type:   domain.PaymentCardSecret,
				}

				// Return existing secret with version 3
				mockSecretDBRepo.EXPECT().
					GetLatestSecretByName(ctx, secret.UserID, secret.Name).
					Return(&domain.Secret{Version: 3}, nil)

				// Expect data secret to be created with version 4
				mockSecretDBRepo.EXPECT().
					CreateSecret(ctx, gomock.Any()).
					DoAndReturn(func(_ context.Context, s *domain.Secret) error {
						assert.Equal(t, int32(4), s.Version)
						return nil
					})
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			err := secretService.CreateSecret(ctx, &tt.secret, tt.secretData)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSecretService_ListSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	conf := config.GetDefault()
	ctx := context.Background()
	userID := "test-user"

	mockSecretDBRepo := mocks.NewMockSecretRepository(ctrl)
	mockSecretObjRepo := mocks.NewMockSecretObjectRepository(ctrl)
	secretService := application.NewSecretService(mockSecretDBRepo, mockSecretObjRepo, []byte(conf.RootKey))

	tests := []struct {
		name            string
		mockSetup       func()
		expectedSecrets []string
		expectedError   error
	}{
		{
			name: "successfully get secrets list",
			mockSetup: func() {
				expectedSecrets := []string{"secret1", "secret2", "secret3"}

				mockSecretDBRepo.EXPECT().
					GetSecretsList(ctx, userID).
					Return(expectedSecrets, nil)
			},
			expectedSecrets: []string{"secret1", "secret2", "secret3"},
			expectedError:   nil,
		},
		{
			name: "empty list when user has no secrets",
			mockSetup: func() {
				mockSecretDBRepo.EXPECT().
					GetSecretsList(ctx, userID).
					Return([]string{}, nil)
			},
			expectedSecrets: []string{},
			expectedError:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			secretsList, err := secretService.GetSecretsList(ctx, userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedSecrets, secretsList)
			}
		})
	}
}

func TestSecretService_DeleteSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	conf := config.GetDefault()
	ctx := context.Background()
	userID := "test-user"
	secretName := "test-secret"

	mockSecretDBRepo := mocks.NewMockSecretRepository(ctrl)
	mockSecretObjRepo := mocks.NewMockSecretObjectRepository(ctrl)
	secretService := application.NewSecretService(mockSecretDBRepo, mockSecretObjRepo, []byte(conf.RootKey))

	tests := []struct {
		name          string
		mockSetup     func()
		expectedError error
	}{
		{
			name: "successfully delete credentials secret",
			mockSetup: func() {
				mockSecretDBRepo.EXPECT().
					GetLatestSecretByName(ctx, userID, secretName).
					Return(&domain.Secret{
						UserID:  userID,
						Name:    secretName,
						Type:    domain.CredentialsSecret,
						Version: 1,
					}, nil)

				mockSecretDBRepo.EXPECT().
					DeleteSecret(ctx, userID, secretName).
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "successfully delete file secret with multiple versions",
			mockSetup: func() {
				mockSecretDBRepo.EXPECT().
					GetLatestSecretByName(ctx, userID, secretName).
					Return(&domain.Secret{
						UserID:  userID,
						Name:    secretName,
						Type:    domain.FileSecret,
						Version: 3,
					}, nil)

				// Expect 3 calls to DeleteFile (one per version)
				mockSecretObjRepo.EXPECT().
					DeleteFile(ctx, gomock.Any()).
					Return(nil).
					Times(3)

				mockSecretDBRepo.EXPECT().
					DeleteSecret(ctx, userID, secretName).
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "fail when secret not found",
			mockSetup: func() {
				mockSecretDBRepo.EXPECT().
					GetLatestSecretByName(ctx, userID, secretName).
					Return(nil, domain.ErrSecretNotFound)
			},
			expectedError: domain.ErrSecretNotFound,
		},
		{
			name: "fail when database error occurs",
			mockSetup: func() {
				mockSecretDBRepo.EXPECT().
					GetLatestSecretByName(ctx, userID, secretName).
					Return(&domain.Secret{
						UserID:  userID,
						Name:    secretName,
						Type:    domain.CredentialsSecret,
						Version: 1,
					}, nil)

				mockSecretDBRepo.EXPECT().
					DeleteSecret(ctx, userID, secretName).
					Return(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
		{
			name: "fail when object storage deletion fails",
			mockSetup: func() {
				mockSecretDBRepo.EXPECT().
					GetLatestSecretByName(ctx, userID, secretName).
					Return(&domain.Secret{
						UserID:  userID,
						Name:    secretName,
						Type:    domain.FileSecret,
						Version: 2,
					}, nil)

				mockSecretObjRepo.EXPECT().
					DeleteFile(ctx, gomock.Any()).
					Return(errors.New("storage error"))
			},
			expectedError: errors.New("storage error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			err := secretService.DeleteSecret(ctx, userID, secretName)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
