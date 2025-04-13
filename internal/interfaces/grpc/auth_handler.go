package grpc

import (
	"context"
	"errors"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen"
)

// AuthHandler manages authentication requests via gRPC.
type AuthHandler struct {
	pb.UnimplementedAuthServer

	service domain.AuthService
	logger  zerolog.Logger
}

// NewAuthHandler creates a new AuthHandler with the given authentication service.
func NewAuthHandler(service domain.AuthService) *AuthHandler {
	return &AuthHandler{
		service: service,
		logger:  log.With().Str("component", "grpc_auth_handler").Logger(),
	}
}

// Login processes user login requests, verifying credentials and returning a JWT token.
func (h *AuthHandler) Login(ctx context.Context, in *pb.AuthRequest) (*pb.AuthResponse, error) {
	login := in.GetLogin()
	password := in.GetPassword()

	logCtx := h.logger.With().
		Str("method", "Login").
		Str("login", login).
		Logger()

	if ok, err := h.validateLoginAndPassword(login, password); !ok {
		logCtx.Warn().Err(err).Msg("empty login or password provided")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	token, err := h.service.Login(ctx, login, password)
	switch {
	case err == nil:
		logCtx.Info().Msg("user logged in successfully")
		return &pb.AuthResponse{Token: token}, nil
	case errors.Is(err, domain.ErrUserNotFound):
		logCtx.Warn().Err(err).Msg(domain.ErrUserNotFound.Error())
		return nil, status.Error(codes.NotFound, domain.ErrUserNotFound.Error())
	default:
		logCtx.Error().Err(err).Msg("login failed")
		return nil, status.Error(codes.Internal, "login failed")
	}

}

// Register processes user registration requests and returns a JWT token upon success.
func (h *AuthHandler) Register(ctx context.Context, in *pb.AuthRequest) (*pb.AuthResponse, error) {
	login := in.GetLogin()
	password := in.GetPassword()

	logCtx := h.logger.With().
		Str("method", "Register").
		Str("login", login).
		Logger()

	if ok, err := h.validateLoginAndPassword(login, password); !ok {
		logCtx.Warn().Err(err).Msg("empty login or password provided")
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	token, err := h.service.Register(ctx, login, password)
	switch {
	case err == nil:
		logCtx.Info().Msg("user registered successfully")
		return &pb.AuthResponse{Token: token}, nil
	case errors.Is(err, domain.ErrLoginExists):
		logCtx.Warn().Err(err).Msg("registration failed")
		return nil, status.Error(codes.AlreadyExists, domain.ErrLoginExists.Error())
	default:
		logCtx.Error().Err(err).Msg("registration failed")
		return nil, status.Error(codes.Internal, "registration failed")
	}
}

func (h *AuthHandler) validateLoginAndPassword(login, password string) (bool, error) {
	if login == "" {
		return false, domain.ErrEmptyLogin
	}

	if password == "" {
		return false, domain.ErrEmptyPassword
	}

	return true, nil
}
