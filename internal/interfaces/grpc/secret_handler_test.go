package grpc_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	pb "github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/interfaces/grpc"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/interfaces/grpc/interceptors"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/mocks"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSecretHandler_CreateSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSecretService := mocks.NewMockSecretService(ctrl)
	handler := grpc.NewSecretHandler(mockSecretService)

	ctx := context.WithValue(context.Background(), interceptors.UserIDContext, "user1")

	tests := []struct {
		name          string
		req           *pb.CreateSecretRequest
		setupMock     func()
		expectedError error
	}{
		{
			name: "successful creation",
			req: &pb.CreateSecretRequest{
				Info: &pb.CreateSecretInfoRequest{
					Name:     "test",
					Type:     pb.SecretType_TEXT,
					Metadata: "meta",
				},
				Data: "secret data",
			},
			setupMock: func() {
				expectedSecret := &domain.Secret{
					Name:     "test",
					Type:     domain.TextSecret,
					Metadata: "meta",
					UserID:   "user1",
					Version:  1,
				}
				mockSecretService.EXPECT().
					CreateSecret(
						gomock.Any(),
						gomock.AssignableToTypeOf(expectedSecret),
						gomock.AssignableToTypeOf(&bytes.Reader{}),
					).
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "invalid secret type",
			req: &pb.CreateSecretRequest{
				Info: &pb.CreateSecretInfoRequest{
					Name:     "test",
					Type:     999, // invalid
					Metadata: "meta",
				},
				Data: "secret data",
			},
			setupMock:     func() {}, // No mock expectations - should fail before service call
			expectedError: status.Error(codes.InvalidArgument, domain.ErrInvalidSecretType.Error()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			_, err := handler.CreateSecret(ctx, tt.req)

			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecretHandler_CreateSecretStream(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockSecretService(ctrl)
	mockStream := mocks.NewMockSecretService_CreateSecretStreamServer(ctrl)
	handler := grpc.NewSecretHandler(mockService)

	ctx := context.WithValue(context.Background(), interceptors.UserIDContext, "user1")
	validInfo := &pb.CreateSecretInfoRequest{
		Name:     "test-secret",
		Type:     pb.SecretType_TEXT,
		Metadata: `{"description": "test data"}`,
	}

	tests := []struct {
		name          string
		setupMock     func()
		expectedError codes.Code
	}{
		{
			name: "successful stream creation",
			setupMock: func() {
				gomock.InOrder(
					mockStream.EXPECT().Context().Return(ctx),
					mockStream.EXPECT().Recv().Return(
						&pb.CreateSecretChunkRequest{
							Chunk: &pb.CreateSecretChunkRequest_Info{Info: validInfo},
						}, nil),
					mockStream.EXPECT().Recv().Return(
						&pb.CreateSecretChunkRequest{
							Chunk: &pb.CreateSecretChunkRequest_Data{Data: []byte("chunk1")},
						}, nil),
					mockStream.EXPECT().Recv().Return(
						&pb.CreateSecretChunkRequest{
							Chunk: &pb.CreateSecretChunkRequest_Data{Data: []byte("chunk2")},
						}, nil),
					mockStream.EXPECT().Recv().Return(nil, io.EOF),
					mockStream.EXPECT().SendAndClose(gomock.Any()).Return(nil),
				)
				mockService.EXPECT().
					CreateSecret(
						ctx,
						gomock.AssignableToTypeOf(&domain.Secret{}),
						gomock.AssignableToTypeOf(grpc.NewSecretStreamReader(nil)),
					).
					DoAndReturn(func(ctx context.Context, secret *domain.Secret, reader io.Reader) error {
						// Verify the secret metadata
						assert.Equal(t, "test-secret", secret.Name)
						assert.Equal(t, domain.TextSecret, secret.Type)

						// Verify we can read the streamed data
						data, err := io.ReadAll(reader)
						assert.NoError(t, err)
						assert.Equal(t, []byte("chunk1chunk2"), data)
						return nil
					})
			},
			expectedError: codes.OK,
		},
		{
			name: "missing info chunk",
			setupMock: func() {
				gomock.InOrder(
					mockStream.EXPECT().Context().Return(ctx),
					mockStream.EXPECT().Recv().Return(
						&pb.CreateSecretChunkRequest{
							Chunk: &pb.CreateSecretChunkRequest_Data{Data: []byte("invalid")},
						}, nil),
				)
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "invalid secret type",
			setupMock: func() {
				invalidInfo := proto.Clone(validInfo).(*pb.CreateSecretInfoRequest)
				invalidInfo.Type = pb.SecretType(999)

				gomock.InOrder(
					mockStream.EXPECT().Context().Return(ctx),
					mockStream.EXPECT().Recv().Return(
						&pb.CreateSecretChunkRequest{
							Chunk: &pb.CreateSecretChunkRequest_Info{Info: invalidInfo},
						}, nil),
				)
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name: "service returns error",
			setupMock: func() {
				gomock.InOrder(
					mockStream.EXPECT().Context().Return(ctx),
					mockStream.EXPECT().Recv().Return(
						&pb.CreateSecretChunkRequest{
							Chunk: &pb.CreateSecretChunkRequest_Info{Info: validInfo},
						}, nil))

				mockService.EXPECT().
					CreateSecret(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(domain.ErrInvalidSecretType)
			},
			expectedError: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := handler.CreateSecretStream(mockStream)
			if tt.expectedError == codes.OK {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, tt.expectedError, status.Code(err))
			}
		})
	}
}

func TestSecretHandler_ListSecrets(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockSecretService(ctrl)
	handler := grpc.NewSecretHandler(mockService)

	ctx := context.WithValue(context.Background(), interceptors.UserIDContext, "user1")

	tests := []struct {
		name           string
		setupMock      func()
		expectedResult *pb.ListSecretsResponse
		expectedError  error
	}{
		{
			name: "successful empty list",
			setupMock: func() {
				mockService.EXPECT().
					GetSecretsList(ctx, "user1").
					Return([]string{}, nil)
			},
			expectedResult: &pb.ListSecretsResponse{Data: []string{}},
			expectedError:  nil,
		},
		{
			name: "successful with multiple secrets",
			setupMock: func() {
				mockService.EXPECT().
					GetSecretsList(ctx, "user1").
					Return([]string{"secret1", "secret2", "secret3"}, nil)
			},
			expectedResult: &pb.ListSecretsResponse{
				Data: []string{"secret1", "secret2", "secret3"},
			},
			expectedError: nil,
		},
		{
			name: "repository error",
			setupMock: func() {
				mockService.EXPECT().
					GetSecretsList(ctx, "user1").
					Return(nil, errors.New("database error"))
			},
			expectedResult: nil,
			expectedError:  status.Error(codes.Internal, "failed to retrieve secrets list"),
		},
		{
			name:           "missing user in context",
			setupMock:      func() {}, // No mock expectations - should fail before service call
			expectedResult: nil,
			expectedError:  status.Error(codes.Unauthenticated, "authentication required"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCtx := ctx
			if tt.name == "missing user in context" {
				testCtx = context.Background() // No user in context
			} else {
				tt.setupMock()
			}

			resp, err := handler.ListSecrets(testCtx, &emptypb.Empty{})

			if tt.expectedError != nil {
				assert.Nil(t, resp)
				assert.Equal(t, tt.expectedError, err)
				if tt.name == "missing user in context" {
					assert.Contains(t, err.Error(), "authentication required")
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, resp)
			}
		})
	}
}

func TestSecretHandler_GetLatestSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockSecretService(ctrl)
	handler := grpc.NewSecretHandler(mockService)

	ctx := context.WithValue(context.Background(), interceptors.UserIDContext, "user1")
	now := time.Now()

	// Common test secret
	testSecret := &domain.Secret{
		ID:        "secret-id",
		Name:      "test-secret",
		UserID:    "user1",
		Type:      domain.TextSecret,
		Data:      []byte("secret data"),
		Metadata:  `{"description":"test secret"}`,
		Version:   3,
		CreatedAt: now,
	}

	tests := []struct {
		name           string
		request        *pb.GetLatestSecretRequest
		setupMock      func()
		expectedResult *pb.GetSecretResponse
		expectedError  *status.Status
	}{
		{
			name:    "successful retrieval",
			request: &pb.GetLatestSecretRequest{Name: "test-secret"},
			setupMock: func() {
				mockService.EXPECT().
					GetLatestSecretByName(ctx, "user1", "test-secret").
					Return(testSecret, nil)
			},
			expectedResult: &pb.GetSecretResponse{
				Info: &pb.GetSecretInfoResponse{
					Name:      "test-secret",
					Type:      pb.SecretType_TEXT,
					Metadata:  `{"description":"test secret"}`,
					Version:   3,
					CreatedAt: timestamppb.New(now),
				},
				Data: "secret data",
			},
		},
		{
			name:    "secret not found",
			request: &pb.GetLatestSecretRequest{Name: "missing-secret"},
			setupMock: func() {
				mockService.EXPECT().
					GetLatestSecretByName(ctx, "user1", "missing-secret").
					Return(nil, domain.ErrSecretNotFound)
			},
			expectedError: status.New(codes.NotFound, domain.ErrSecretNotFound.Error()),
		},
		{
			name:          "empty secret name",
			request:       &pb.GetLatestSecretRequest{Name: ""},
			setupMock:     func() {}, // No mock expectations - should fail before service call
			expectedError: status.New(codes.InvalidArgument, domain.ErrEmptySecretName.Error()),
		},
		{
			name:    "repository error",
			request: &pb.GetLatestSecretRequest{Name: "test-secret"},
			setupMock: func() {
				mockService.EXPECT().
					GetLatestSecretByName(ctx, "user1", "test-secret").
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: status.New(codes.Internal, "failed to get latest secret"),
		},
		{
			name:          "missing user context",
			request:       &pb.GetLatestSecretRequest{Name: "test-secret"},
			setupMock:     func() {}, // No mock expectations - should fail before service call
			expectedError: status.New(codes.Unauthenticated, "authentication required"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare test context
			testCtx := ctx
			if tt.name == "missing user context" {
				testCtx = context.Background()
			}

			tt.setupMock()

			resp, err := handler.GetLatestSecret(testCtx, tt.request)

			// Verify error cases
			if tt.expectedError != nil {
				assert.Nil(t, resp)
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.expectedError.Code(), st.Code())
				assert.Contains(t, st.Message(), tt.expectedError.Message())

				return
			}

			// Verify success cases
			require.NoError(t, err)
			require.NotNil(t, resp)

			// Verify response content
			assert.Equal(t, tt.expectedResult.Data, resp.Data)
			assert.Equal(t, tt.expectedResult.Info.Name, resp.Info.Name)
			assert.Equal(t, tt.expectedResult.Info.Type, resp.Info.Type)
			assert.Equal(t, tt.expectedResult.Info.Metadata, resp.Info.Metadata)
			assert.Equal(t, tt.expectedResult.Info.Version, resp.Info.Version)
			assert.WithinDuration(t, tt.expectedResult.Info.CreatedAt.AsTime(), resp.Info.CreatedAt.AsTime(), time.Second)
		})
	}
}

func TestSecretHandler_GetSecretByVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockSecretService(ctrl)
	handler := grpc.NewSecretHandler(mockService)

	ctx := context.WithValue(context.Background(), interceptors.UserIDContext, "user1")
	now := time.Now().UTC()
	testSecret := &domain.Secret{
		ID:        "secret-id-123",
		Name:      "test-secret",
		UserID:    "user1",
		Type:      domain.CredentialsSecret,
		Data:      []byte(`{"username":"admin","password":"s3cr3t"}`),
		Metadata:  `{"tags":["prod","admin"]}`,
		Version:   2,
		CreatedAt: now,
	}

	tests := []struct {
		name           string
		request        *pb.GetSecretByVersionRequest
		setupMock      func()
		expectedResult *pb.GetSecretResponse
		expectedError  *status.Status
	}{
		{
			name: "successful retrieval by version",
			request: &pb.GetSecretByVersionRequest{
				Name:    "test-secret",
				Version: 2,
			},
			setupMock: func() {
				mockService.EXPECT().
					GetSecretByVersion(ctx, "user1", "test-secret", int32(2)).
					Return(testSecret, nil)
			},
			expectedResult: &pb.GetSecretResponse{
				Info: &pb.GetSecretInfoResponse{
					Name:      "test-secret",
					Type:      pb.SecretType_CREDENTIALS,
					Metadata:  `{"tags":["prod","admin"]}`,
					Version:   2,
					CreatedAt: timestamppb.New(now),
				},
				Data: `{"username":"admin","password":"s3cr3t"}`,
			},
		},
		{
			name: "secret not found",
			request: &pb.GetSecretByVersionRequest{
				Name:    "nonexistent-secret",
				Version: 1,
			},
			setupMock: func() {
				mockService.EXPECT().
					GetSecretByVersion(ctx, "user1", "nonexistent-secret", int32(1)).
					Return(nil, domain.ErrSecretNotFound)
			},
			expectedError: status.New(codes.NotFound, domain.ErrSecretNotFound.Error()),
		},
		{
			name: "version not found",
			request: &pb.GetSecretByVersionRequest{
				Name:    "test-secret",
				Version: 99,
			},
			setupMock: func() {
				mockService.EXPECT().
					GetSecretByVersion(ctx, "user1", "test-secret", int32(99)).
					Return(nil, domain.ErrSecretVersionNotFound)
			},
			expectedError: status.New(codes.NotFound, domain.ErrSecretVersionNotFound.Error()),
		},
		{
			name: "invalid request - empty name",
			request: &pb.GetSecretByVersionRequest{
				Name:    "",
				Version: 1,
			},
			expectedError: status.New(codes.InvalidArgument, domain.ErrEmptySecretName.Error()),
		},
		{
			name: "invalid request - invalid version",
			request: &pb.GetSecretByVersionRequest{
				Name:    "test-secret",
				Version: 0, // invalid version
			},
			expectedError: status.New(codes.InvalidArgument, domain.ErrNonPositiveSecretVersion.Error()),
		},
		{
			name: "repository error",
			request: &pb.GetSecretByVersionRequest{
				Name:    "test-secret",
				Version: 2,
			},
			setupMock: func() {
				mockService.EXPECT().
					GetSecretByVersion(ctx, "user1", "test-secret", int32(2)).
					Return(nil, errors.New("database connection failed"))
			},
			expectedError: status.New(codes.Internal, "failed to get secret by version"),
		},
		{
			name: "missing user context",
			request: &pb.GetSecretByVersionRequest{
				Name:    "test-secret",
				Version: 2,
			},
			expectedError: status.New(codes.Unauthenticated, "authentication required"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare test context
			testCtx := ctx
			if tt.name == "missing user context" {
				testCtx = context.Background()
			} else if tt.setupMock != nil {
				tt.setupMock()
			}

			resp, err := handler.GetSecretByVersion(testCtx, tt.request)

			// Verify error cases
			if tt.expectedError != nil {
				assert.Nil(t, resp)
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.expectedError.Code(), st.Code())
				assert.Contains(t, st.Message(), tt.expectedError.Message())

				return
			}

			// Verify success case
			require.NoError(t, err)
			require.NotNil(t, resp)

			// Verify response content
			assert.Equal(t, tt.expectedResult.Data, resp.Data)
			assert.Equal(t, tt.expectedResult.Info.Name, resp.Info.Name)
			assert.Equal(t, tt.expectedResult.Info.Type, resp.Info.Type)
			assert.Equal(t, tt.expectedResult.Info.Metadata, resp.Info.Metadata)
			assert.Equal(t, tt.expectedResult.Info.Version, resp.Info.Version)
			assert.WithinDuration(t, tt.expectedResult.Info.CreatedAt.AsTime(), resp.Info.CreatedAt.AsTime(), time.Second)
		})
	}
}

func TestSecretHandler_GetLatestSecretStream(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockSecretService(ctrl)
	recorder := mocks.NewMockSecretService_GetLatestSecretStreamServer(ctrl)
	handler := grpc.NewSecretHandler(mockService)

	ctx := context.WithValue(context.Background(), interceptors.UserIDContext, "user1")
	now := time.Now().UTC()

	tests := []struct {
		name          string
		secretName    string
		setupMock     func()
		expectedError codes.Code
	}{
		{
			name:       "successful small text stream",
			secretName: "text-secret",
			setupMock: func() {
				secret := &domain.Secret{
					Name:      "text-secret",
					Type:      domain.TextSecret,
					Data:      []byte("small data chunk"),
					Metadata:  `{"encoding":"utf8"}`,
					Version:   1,
					CreatedAt: now,
				}

				mockService.EXPECT().
					GetLatestSecretStreamByName(gomock.Any(), "user1", "text-secret").
					Return(secret, io.NopCloser(bytes.NewReader(secret.Data)), nil)

				gomock.InOrder(
					recorder.EXPECT().Context().Return(ctx),
					recorder.EXPECT().Send(&pb.GetSecretChunkResponse{
						Chunk: &pb.GetSecretChunkResponse_Info{
							Info: &pb.GetSecretInfoResponse{
								Name:      secret.Name,
								Metadata:  secret.Metadata,
								Type:      pb.SecretType_TEXT,
								Version:   secret.Version,
								CreatedAt: timestamppb.New(secret.CreatedAt),
							},
						},
					}).Return(nil),
					recorder.EXPECT().Send(&pb.GetSecretChunkResponse{
						Chunk: &pb.GetSecretChunkResponse_Data{
							Data: secret.Data,
						},
					}).Return(nil),
				)
			},
		},
		{
			name:       "empty secret name",
			secretName: "",
			setupMock: func() {
				recorder.EXPECT().Context().Return(ctx)
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name:       "secret not found",
			secretName: "missing-secret",
			setupMock: func() {
				mockService.EXPECT().
					GetLatestSecretStreamByName(gomock.Any(), "user1", "missing-secret").
					Return(nil, nil, domain.ErrSecretNotFound)

				recorder.EXPECT().Context().Return(ctx)
			},
			expectedError: codes.NotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			if tt.setupMock != nil {
				tt.setupMock()
			}

			// Execute
			err := handler.GetLatestSecretStream(
				&pb.GetLatestSecretRequest{Name: tt.secretName},
				recorder,
			)

			// Verify
			if tt.expectedError != codes.OK {
				require.Error(t, err)
				assert.Equal(t, tt.expectedError, status.Code(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSecretHandler_GetSecretStreamByVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockSecretService(ctrl)
	recorder := mocks.NewMockSecretService_GetLatestSecretStreamServer(ctrl)
	handler := grpc.NewSecretHandler(mockService)

	ctx := context.WithValue(context.Background(), interceptors.UserIDContext, "user1")
	now := time.Now().UTC()

	tests := []struct {
		name          string
		secretName    string
		secretVersion int32
		setupMock     func()
		expectedError codes.Code
	}{
		{
			name:          "successful small text stream",
			secretName:    "text-secret",
			secretVersion: 1,
			setupMock: func() {
				secret := &domain.Secret{
					Name:      "text-secret",
					Type:      domain.TextSecret,
					Data:      []byte("small data chunk"),
					Metadata:  `{"encoding":"utf8"}`,
					Version:   1,
					CreatedAt: now,
				}

				mockService.EXPECT().
					GetSecretStreamByVersion(gomock.Any(), "user1", "text-secret", int32(1)).
					Return(secret, io.NopCloser(bytes.NewReader(secret.Data)), nil)

				gomock.InOrder(
					recorder.EXPECT().Context().Return(ctx),
					recorder.EXPECT().Send(&pb.GetSecretChunkResponse{
						Chunk: &pb.GetSecretChunkResponse_Info{
							Info: &pb.GetSecretInfoResponse{
								Name:      secret.Name,
								Metadata:  secret.Metadata,
								Type:      pb.SecretType_TEXT,
								Version:   secret.Version,
								CreatedAt: timestamppb.New(secret.CreatedAt),
							},
						},
					}).Return(nil),
					recorder.EXPECT().Send(&pb.GetSecretChunkResponse{
						Chunk: &pb.GetSecretChunkResponse_Data{
							Data: secret.Data,
						},
					}).Return(nil),
				)
			},
		},
		{
			name:          "empty secret name",
			secretName:    "",
			secretVersion: 1,
			setupMock: func() {
				recorder.EXPECT().Context().Return(ctx)
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name:          "non positive secret version",
			secretName:    "secret-name",
			secretVersion: -1,
			setupMock: func() {
				recorder.EXPECT().Context().Return(ctx)
			},
			expectedError: codes.InvalidArgument,
		},
		{
			name:          "secret not found",
			secretName:    "missing-secret",
			secretVersion: 1,
			setupMock: func() {
				mockService.EXPECT().
					GetSecretStreamByVersion(gomock.Any(), "user1", "missing-secret", int32(1)).
					Return(nil, nil, domain.ErrSecretNotFound)

				recorder.EXPECT().Context().Return(ctx)
			},
			expectedError: codes.NotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			if tt.setupMock != nil {
				tt.setupMock()
			}

			// Execute
			err := handler.GetSecretStreamByVersion(
				&pb.GetSecretByVersionRequest{Name: tt.secretName, Version: tt.secretVersion},
				recorder,
			)

			// Verify
			if tt.expectedError != codes.OK {
				require.Error(t, err)
				assert.Equal(t, tt.expectedError, status.Code(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSecretHandler_DeleteSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockSecretService(ctrl)
	handler := grpc.NewSecretHandler(mockService)

	ctx := context.WithValue(context.Background(), interceptors.UserIDContext, "user1")

	tests := []struct {
		name          string
		request       *pb.DeleteSecretRequest
		setupMock     func()
		expectedError *status.Status
	}{
		{
			name:    "successful deletion",
			request: &pb.DeleteSecretRequest{Name: "valid-secret"},
			setupMock: func() {
				mockService.EXPECT().
					DeleteSecret(ctx, "user1", "valid-secret").
					Return(nil)
			},
		},
		{
			name:    "secret not found",
			request: &pb.DeleteSecretRequest{Name: "missing-secret"},
			setupMock: func() {
				mockService.EXPECT().
					DeleteSecret(ctx, "user1", "missing-secret").
					Return(domain.ErrSecretNotFound)
			},
			expectedError: status.New(codes.NotFound, domain.ErrSecretNotFound.Error()),
		},
		{
			name:          "empty secret name",
			request:       &pb.DeleteSecretRequest{Name: ""},
			expectedError: status.New(codes.InvalidArgument, domain.ErrEmptySecretName.Error()),
		},
		{
			name:    "repository error",
			request: &pb.DeleteSecretRequest{Name: "db-error-secret"},
			setupMock: func() {
				mockService.EXPECT().
					DeleteSecret(ctx, "user1", "db-error-secret").
					Return(errors.New("database connection failed"))
			},
			expectedError: status.New(codes.Internal, "failed to delete secret"),
		},
		{
			name:          "missing user context",
			request:       &pb.DeleteSecretRequest{Name: "any-secret"},
			expectedError: status.New(codes.Unauthenticated, "authentication required"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare test context
			testCtx := ctx
			if tt.name == "missing user context" {
				testCtx = context.Background()
			} else if tt.setupMock != nil {
				tt.setupMock()
			}

			// Execute
			resp, err := handler.DeleteSecret(testCtx, tt.request)

			// Verify
			if tt.expectedError != nil {
				assert.Nil(t, resp)
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.expectedError.Code(), st.Code())
				assert.Contains(t, st.Message(), tt.expectedError.Message())
			} else {
				assert.NotNil(t, resp)
				assert.IsType(t, &emptypb.Empty{}, resp)
				assert.NoError(t, err)
			}
		})
	}
}
