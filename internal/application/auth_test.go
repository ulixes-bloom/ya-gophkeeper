package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/application"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/config"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/mocks"
)

func TestAuthService_Register(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	conf := config.GetDefault()
	ctx := context.Background()

	mockSecretRepo := mocks.NewMockUserRepository(ctrl)
	authService := application.NewAuthService(mockSecretRepo, conf.JWTTokenBuildKey, conf.JWTTokenLifetime)

	tests := []struct {
		name          string
		login         string
		password      string
		mockSetup     func()
		expectedError error
	}{
		{
			name:     "successful registration",
			login:    "testuser",
			password: "testpass",
			mockSetup: func() {
				mockSecretRepo.EXPECT().CreateUser(ctx, "testuser", gomock.Any()).
					Return(&domain.User{ID: "user123", Login: "testuser", PasswordHash: ""}, nil)
			},
			expectedError: nil,
		},
		{
			name:     "duplicate login",
			login:    "existinguser",
			password: "testpass",
			mockSetup: func() {
				mockSecretRepo.EXPECT().CreateUser(ctx, "existinguser", gomock.Any()).
					Return(&domain.User{}, domain.ErrLoginExists)
			},
			expectedError: domain.ErrLoginExists,
		},
		{
			name:     "token generation error",
			login:    "testuser",
			password: "testpass",
			mockSetup: func() {
				mockSecretRepo.EXPECT().CreateUser(ctx, "testuser", gomock.Any()).
					Return(&domain.User{ID: "", Login: "testuser", PasswordHash: "hashed_testpass"}, nil)
			},
			expectedError: errors.New("userID cannot be empty"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			token, err := authService.Register(ctx, tt.login, tt.password)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Empty(t, token)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, token)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	conf := config.GetDefault()
	ctx := context.Background()

	mockSecretRepo := mocks.NewMockUserRepository(ctrl)
	authService := application.NewAuthService(mockSecretRepo, conf.JWTTokenBuildKey, conf.JWTTokenLifetime)

	tests := []struct {
		name          string
		login         string
		password      string
		mockSetup     func()
		expectedError error
	}{
		{
			name:     "successful login",
			login:    "testuser",
			password: "testpass",
			mockSetup: func() {
				mockSecretRepo.EXPECT().FindUserByLogin(ctx, "testuser").
					Return(&domain.User{ID: "user123", Login: "testuser", PasswordHash: "$2a$10$6zCkWJEf4JTAEop5ue.fQu9ygjLxed0cMfgcm2QwZDBPUSFBQHXZm"}, nil)
			},
			expectedError: nil,
		},
		{
			name:     "not existing login",
			login:    "existinguser",
			password: "testpass",
			mockSetup: func() {
				mockSecretRepo.EXPECT().FindUserByLogin(ctx, "existinguser").
					Return(&domain.User{}, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:     "token generation error",
			login:    "testuser",
			password: "testpass",
			mockSetup: func() {
				mockSecretRepo.EXPECT().FindUserByLogin(ctx, "testuser").
					Return(&domain.User{ID: "", Login: "testuser", PasswordHash: "$2a$10$6zCkWJEf4JTAEop5ue.fQu9ygjLxed0cMfgcm2QwZDBPUSFBQHXZm"}, nil)
			},
			expectedError: errors.New("userID cannot be empty"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			token, err := authService.Login(ctx, tt.login, tt.password)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Empty(t, token)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, token)
			}
		})
	}
}
