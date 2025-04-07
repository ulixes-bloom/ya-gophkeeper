package grpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	pb "github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	chunkSize = 1024 * 512 // 500B chunk size for streaming
)

// SecretHandler implements the gRPC server for managing secrets.
type SecretHandler struct {
	pb.UnimplementedSecretServiceServer

	service domain.SecretService
	logger  zerolog.Logger
}

// NewSecretHandler initializes a new SecretHandler with the provided service.
func NewSecretHandler(service domain.SecretService) *SecretHandler {
	return &SecretHandler{
		service: service,
		logger:  log.With().Str("component", "grpc_secret_handler").Logger(),
	}
}

// CreateSecret handles the creation of a new data secret.
// Returns an empty response if successful or an error otherwise.
func (h *SecretHandler) CreateSecret(ctx context.Context, in *pb.CreateSecretRequest) (*emptypb.Empty, error) {
	userID, err := extractUserID(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to extract user ID")
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	logCtx := h.logger.With().
		Str("method", "CreateSecret").
		Str("user_id", userID).
		Logger()

	if ok, err := h.validateCreateSecretRequest(in.GetInfo()); !ok {
		logCtx.Error().Err(err).Msg("secret info not valid")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	domainSecret := mapProtoCreateSecretInfoRequestToDomainSecret(in.GetInfo(), userID)
	contentReader := bytes.NewReader([]byte(in.GetData()))

	if err := h.service.CreateSecret(ctx, domainSecret, contentReader); err != nil {
		logCtx := logCtx.With().
			Err(err).
			Str("secret_name", domainSecret.Name).
			Any("secret_type", domainSecret.Type).
			Str("secret_metadata", domainSecret.Metadata).
			Logger()

		if errors.Is(err, domain.ErrInvalidSecretType) {
			logCtx.Warn().Msg("invalid secret type")
			return nil, status.Error(codes.InvalidArgument, domain.ErrInvalidSecretType.Error())
		}

		logCtx.Error().Msg("failed to create secret")
		return nil, status.Error(codes.Internal, "failed to create secret")
	}

	logCtx.Info().
		Str("secret_name", domainSecret.Name).
		Msg("secret created successfully")

	return &emptypb.Empty{}, nil
}

// CreateSecretStream handles stream-based secret creation.
// It accepts a stream of data chunks, processes the secret's metadata and data, and then creates the secret.
func (h *SecretHandler) CreateSecretStream(stream pb.SecretService_CreateSecretStreamServer) error {
	ctx := stream.Context()

	userID, err := extractUserID(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to extract user ID")
		return status.Error(codes.Unauthenticated, "authentication required")
	}

	logCtx := h.logger.With().
		Str("method", "CreateSecretStream").
		Str("user_id", userID).
		Logger()

	// Read the first chunk to get metadata
	firstChunk, err := stream.Recv()
	if err != nil {
		logCtx.Error().Msg("failed to receive first chunk")
		return status.Error(codes.Internal, "failed to receive initial data")
	}

	// Extract secret info from first chunk
	secretInfo := firstChunk.GetInfo()
	if ok, err := h.validateCreateSecretRequest(secretInfo); !ok {
		logCtx.Error().Err(err).Msg("secret info not valid")
		return status.Error(codes.InvalidArgument, err.Error())
	}

	domainSecret := mapProtoCreateSecretInfoRequestToDomainSecret(secretInfo, userID)
	reader := NewSecretStreamReader(stream)

	if err := h.service.CreateSecret(ctx, domainSecret, reader); err != nil {
		logCtx := logCtx.With().
			Err(err).
			Str("secret_name", domainSecret.Name).
			Any("secret_type", domainSecret.Type).
			Str("secret_metadata", domainSecret.Metadata).
			Logger()

		if errors.Is(err, domain.ErrInvalidSecretType) {
			logCtx.Warn().Msg("invalid secret type")
			return status.Error(codes.InvalidArgument, domain.ErrInvalidSecretType.Error())
		}

		logCtx.Error().Msg("failed to create secret from stream")
		return status.Error(codes.Internal, "failed to create secret")
	}

	// Once the secret is created and all data is processed, send an empty response to indicate success
	if err := stream.SendAndClose(&emptypb.Empty{}); err != nil {
		logCtx.Error().Err(err).Msg("failed to send final response")
		return status.Error(codes.Internal, "failed to send final response")
	}

	logCtx.Info().
		Str("secret_name", domainSecret.Name).
		Msg("secret created successfully from stream")
	return nil
}

// ListSecrets retrieves a list of secrets for a user.
func (h *SecretHandler) ListSecrets(ctx context.Context, in *emptypb.Empty) (*pb.ListSecretsResponse, error) {
	userID, err := extractUserID(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to extract user ID")
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	logCtx := h.logger.With().
		Str("method", "ListSecrets").
		Str("user_id", userID).
		Logger()

	secrets, err := h.service.GetSecretsList(ctx, userID)
	if err != nil {
		logCtx.Error().Err(err).Msg("failed to retrieve secrets list")
		return nil, status.Error(codes.Internal, "failed to retrieve secrets list")
	}

	logCtx.Info().Int("count", len(secrets)).Msg("secrets list retrieved")
	return &pb.ListSecretsResponse{Data: secrets}, nil
}

// GetLatestSecret retrieves the latest version of a secret by its name.
func (h *SecretHandler) GetLatestSecret(ctx context.Context, in *pb.GetLatestSecretRequest) (*pb.GetSecretResponse, error) {
	userID, err := extractUserID(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to extract user ID")
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	secretName := in.GetName()

	logCtx := h.logger.With().
		Str("method", "GetLatestSecret").
		Str("user_id", userID).
		Str("secret_name", secretName).
		Logger()

	if ok, err := h.validateSecretNameNotEmpty(secretName); !ok {
		logCtx.Error().Err(err).Msg("secret name not valid")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	domainSecret, err := h.service.GetLatestSecretByName(ctx, userID, secretName)
	if err != nil {
		if errors.Is(err, domain.ErrSecretNotFound) {
			logCtx.Warn().Err(err).Msg("secret not found")
			return nil, status.Error(codes.NotFound, domain.ErrSecretNotFound.Error())
		}
		logCtx.Error().Err(err).Msg("failed to get latest secret")
		return nil, status.Error(codes.Internal, "failed to get latest secret")
	}

	logCtx.Info().Msg("secret retrieved successfully")
	return &pb.GetSecretResponse{
		Info: mapDomainSecretToProtoGetSecretInfoResponse(domainSecret),
		Data: string(domainSecret.Data),
	}, nil
}

// GetSecretByVersion retrieves a specific version of a secret
func (h *SecretHandler) GetSecretByVersion(ctx context.Context, in *pb.GetSecretByVersionRequest) (*pb.GetSecretResponse, error) {
	userID, err := extractUserID(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to extract user ID")
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	secretName := in.GetName()
	secretVersion := in.GetVersion()

	logCtx := h.logger.With().
		Str("method", "GetSecretByVersion").
		Str("user_id", userID).
		Str("secret_name", secretName).
		Int32("secret_version", secretVersion).
		Logger()

	if ok, err := h.validateSecretNameNotEmpty(secretName); !ok {
		logCtx.Error().Err(err).Msg("secret name not valid")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if ok, err := h.validateSecretVersionPositive(secretVersion); !ok {
		logCtx.Error().Err(err).Msg("secret name not valid")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	domainSecret, err := h.service.GetSecretByVersion(ctx, userID, secretName, secretVersion)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrSecretNotFound):
			logCtx.Warn().Err(err).Msg("secret not found")
			return nil, status.Error(codes.NotFound, domain.ErrSecretNotFound.Error())
		case errors.Is(err, domain.ErrSecretVersionNotFound):
			logCtx.Warn().Err(err).Msg("secret version not found")
			return nil, status.Error(codes.NotFound, domain.ErrSecretVersionNotFound.Error())
		default:
			logCtx.Error().Err(err).Msg("failed to get secret by version")
			return nil, status.Error(codes.Internal, "failed to get secret by version")
		}
	}

	logCtx.Info().Msg("secret version retrieved successfully")
	return &pb.GetSecretResponse{
		Info: mapDomainSecretToProtoGetSecretInfoResponse(domainSecret),
		Data: string(domainSecret.Data),
	}, nil
}

// GetLatestSecretStream streams the latest secret's data by chunks.
func (h *SecretHandler) GetLatestSecretStream(in *pb.GetLatestSecretRequest, stream pb.SecretService_GetLatestSecretStreamServer) error {
	ctx := stream.Context()

	userID, err := extractUserID(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to extract user ID")
		return status.Error(codes.Unauthenticated, "authentication required")
	}

	secretName := in.GetName()
	logCtx := h.logger.With().
		Str("method", "GetLatestSecretStream").
		Str("user_id", userID).
		Str("secret_name", secretName).
		Logger()

	if ok, err := h.validateSecretNameNotEmpty(secretName); !ok {
		logCtx.Error().Err(err).Msg("secret name not valid")
		return status.Error(codes.InvalidArgument, err.Error())
	}

	secret, secretReader, err := h.service.GetLatestSecretStreamByName(ctx, userID, secretName)
	if err != nil {
		if errors.Is(err, domain.ErrSecretNotFound) {
			logCtx.Warn().Err(err).Msg("secret not found")
			return status.Error(codes.NotFound, domain.ErrSecretNotFound.Error())
		}
		logCtx.Error().Err(err).Msg("failed to get latest secret stream")
		return status.Error(codes.Internal, "failed to get latest secret stream")
	}
	defer secretReader.Close()

	// send first chunk with secret metadata
	if err := h.sendMetadataChunk(stream, secret); err != nil {
		logCtx.Error().Err(err).Msg("failed to send metadata chunk")
		return status.Error(codes.Internal, "failed to send metadata")
	}

	// Read the secret data in chunks and send each chunk to the client
	if err := h.sendDataChunks(stream, secretReader); err != nil {
		logCtx.Error().Err(err).Msg("failed to send data chunks")
		return status.Error(codes.Internal, "failed to stream data")
	}

	logCtx.Info().Msg("secret streamed successfully")
	return nil
}

// GetSecretStreamByVersion streams a specific version of a secret in chunks
func (h *SecretHandler) GetSecretStreamByVersion(in *pb.GetSecretByVersionRequest, stream pb.SecretService_GetSecretStreamByVersionServer) error {
	ctx := stream.Context()

	userID, err := extractUserID(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to extract user ID")
		return status.Error(codes.Unauthenticated, "authentication required")
	}

	secretName := in.GetName()
	secretVersion := in.GetVersion()
	logCtx := h.logger.With().
		Str("method", "GetSecretStreamByVersion").
		Str("user_id", userID).
		Str("secret_name", secretName).
		Int32("secret_version", secretVersion).
		Logger()

	if ok, err := h.validateSecretNameNotEmpty(secretName); !ok {
		logCtx.Error().Err(err).Msg("secret name not valid")
		return status.Error(codes.InvalidArgument, err.Error())
	}

	if ok, err := h.validateSecretVersionPositive(secretVersion); !ok {
		logCtx.Error().Err(err).Msg("secret name not valid")
		return status.Error(codes.InvalidArgument, err.Error())
	}

	secret, secretReader, err := h.service.GetSecretStreamByVersion(ctx, userID, secretName, secretVersion)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrSecretNotFound):
			logCtx.Warn().Err(err).Msg(domain.ErrSecretNotFound.Error())
			return status.Error(codes.NotFound, domain.ErrSecretNotFound.Error())
		case errors.Is(err, domain.ErrSecretVersionNotFound):
			logCtx.Warn().Err(err).Msg(domain.ErrSecretVersionNotFound.Error())
			return status.Error(codes.NotFound, domain.ErrSecretVersionNotFound.Error())
		default:
			logCtx.Error().Err(err).Msg("failed to get a spcific secret stream version")
			return status.Error(codes.Internal, "failed to get a spcific secret stream version")
		}
	}
	defer secretReader.Close()

	// send first chunk with secret information
	if err := h.sendMetadataChunk(stream, secret); err != nil {
		logCtx.Error().Err(err).Msg("failed to send secret metadata")
		return status.Error(codes.Internal, "failed to send secret metadata")
	}

	// Read the secret data in chunks and send each chunk to the client
	if err := h.sendDataChunks(stream, secretReader); err != nil {
		logCtx.Error().Err(err).Msg("failed to send secret chunk")
		return status.Error(codes.Internal, "failed to send secret chunk")
	}

	return nil
}

// DeleteSecret deletes a specific secret by name.
func (h *SecretHandler) DeleteSecret(ctx context.Context, in *pb.DeleteSecretRequest) (*emptypb.Empty, error) {
	userID, err := extractUserID(ctx)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to extract user ID")
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	secretName := in.GetName()
	logCtx := h.logger.With().
		Str("method", "DeleteSecret").
		Str("user_id", userID).
		Str("secret_name", secretName).
		Logger()

	if ok, err := h.validateSecretNameNotEmpty(secretName); !ok {
		logCtx.Error().Err(err).Msg("secret name not valid")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := h.service.DeleteSecret(ctx, userID, in.GetName()); err != nil {
		if errors.Is(err, domain.ErrSecretNotFound) {
			logCtx.Warn().Err(err).Msg(domain.ErrSecretNotFound.Error())
			return nil, status.Error(codes.NotFound, domain.ErrSecretNotFound.Error())
		}
		logCtx.Error().Err(err).Msg("failed to delete secret")
		return nil, status.Error(codes.Internal, "failed to delete secret")
	}

	logCtx.Info().Msg("secret deleted successfully")
	return &emptypb.Empty{}, nil
}

func (h *SecretHandler) validateCreateSecretRequest(info *pb.CreateSecretInfoRequest) (bool, error) {
	if info == nil {
		return false, domain.ErrEmptySecretInfo
	}

	if _, ok := pb.SecretType_name[int32(info.GetType())]; !ok {
		return false, domain.ErrInvalidSecretType
	}

	if ok, err := h.validateSecretNameNotEmpty(info.Name); !ok {
		return false, err
	}

	return true, nil
}

func (h *SecretHandler) validateSecretNameNotEmpty(name string) (bool, error) {
	if name == "" {
		return false, domain.ErrEmptySecretName
	}

	return true, nil
}

func (h *SecretHandler) validateSecretVersionPositive(version int32) (bool, error) {
	if version <= 0 {
		return false, domain.ErrNonPositiveSecretVersion
	}

	return true, nil
}

func (h *SecretHandler) sendMetadataChunk(stream pb.SecretService_GetLatestSecretStreamServer, secret *domain.Secret) error {
	return stream.Send(&pb.GetSecretChunkResponse{
		Chunk: &pb.GetSecretChunkResponse_Info{
			Info: mapDomainSecretToProtoGetSecretInfoResponse(secret),
		},
	})
}

func (h *SecretHandler) sendDataChunks(stream pb.SecretService_GetLatestSecretStreamServer, reader io.Reader) error {
	buffer := make([]byte, chunkSize)
	for {
		n, err := reader.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("failed to read data chunk from reader: %w", err)
		}
		chunk := &pb.GetSecretChunkResponse{
			Chunk: &pb.GetSecretChunkResponse_Data{
				Data: buffer[:n],
			},
		}

		if err := stream.Send(chunk); err != nil {
			return fmt.Errorf("failed to send data chunk to stream: %w", err)
		}
	}
	return nil
}
