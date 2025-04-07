package grpc_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	pb "github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/interfaces/grpc"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/mocks"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthHandler_Register(t *testing.T) {
	tests := []struct {
		name          string
		req           *pb.AuthRequest
		setupMock     func(*mocks.MockAuthService)
		expectedError error
	}{
		{
			name: "successful registration",
			req:  &pb.AuthRequest{Login: "login", Password: "password"},
			setupMock: func(m *mocks.MockAuthService) {
				m.EXPECT().Register(gomock.Any(), "login", "password").
					Return("token123", nil)
			},
			expectedError: nil,
		},
		{
			name: "duplicate login",
			req:  &pb.AuthRequest{Login: "login", Password: "password"},
			setupMock: func(m *mocks.MockAuthService) {
				m.EXPECT().Register(gomock.Any(), "login", "password").
					Return("", domain.ErrLoginExists)
			},
			expectedError: status.Error(codes.AlreadyExists, domain.ErrLoginExists.Error()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthService := mocks.NewMockAuthService(ctrl)
			tt.setupMock(mockAuthService)

			handler := grpc.NewAuthHandler(mockAuthService)
			resp, err := handler.Register(context.Background(), tt.req)

			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "token123", resp.GetToken())
			}
		})
	}
}

func TestAuthHandler_Login(t *testing.T) {
	tests := []struct {
		name          string
		req           *pb.AuthRequest
		setupMock     func(*mocks.MockAuthService)
		expectedError error
	}{
		{
			name: "successful login",
			req:  &pb.AuthRequest{Login: "login", Password: "password"},
			setupMock: func(m *mocks.MockAuthService) {
				m.EXPECT().Login(gomock.Any(), "login", "password").
					Return("token123", nil)
			},
			expectedError: nil,
		},
		{
			name: "already existing login",
			req:  &pb.AuthRequest{Login: "login", Password: "password"},
			setupMock: func(m *mocks.MockAuthService) {
				m.EXPECT().Login(gomock.Any(), "login", "password").
					Return("", domain.ErrUserNotFound)
			},
			expectedError: status.Error(codes.NotFound, domain.ErrUserNotFound.Error()),
		},
		{
			name:          "empty login",
			req:           &pb.AuthRequest{Login: "", Password: "password"},
			setupMock:     func(m *mocks.MockAuthService) {},
			expectedError: status.Error(codes.InvalidArgument, domain.ErrEmptyLogin.Error()),
		},
		{
			name:          "empty password",
			req:           &pb.AuthRequest{Login: "login", Password: ""},
			setupMock:     func(m *mocks.MockAuthService) {},
			expectedError: status.Error(codes.InvalidArgument, domain.ErrEmptyPassword.Error()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAuthService := mocks.NewMockAuthService(ctrl)
			tt.setupMock(mockAuthService)

			handler := grpc.NewAuthHandler(mockAuthService)
			resp, err := handler.Login(context.Background(), tt.req)

			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, "token123", resp.GetToken())
			}
		})
	}
}
