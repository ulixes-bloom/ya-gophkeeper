package interceptors

import (
	"context"
	"errors"
	"strings"

	"github.com/ulixes-bloom/ya-gophkeeper/pkg/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	UserIDContext string = "userID" // Key used to store userID in the context
)

// AuthInterceptor struct holds the secretKey for token validation
type AuthInterceptor struct {
	secretKey string
}

// NewJWTInterceptor creates a new AuthInterceptor with the provided secretKey
func NewJWTInterceptor(secretKey string) *AuthInterceptor {
	return &AuthInterceptor{
		secretKey: secretKey,
	}
}

// UnaryInterceptor intercepts unary RPCs to perform authentication
func (i *AuthInterceptor) UnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	if i.requiresAuth(info.FullMethod) {
		token, err := i.extractToken(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "token is required")
		}

		userID, err := security.GetUserID(token, i.secretKey)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		ctx = context.WithValue(ctx, UserIDContext, userID)
	}

	return handler(ctx, req)
}

// StreamInterceptor intercepts streaming RPCs to perform authentication
func (i *AuthInterceptor) StreamInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if i.requiresAuth(info.FullMethod) {
		token, err := i.extractToken(ss.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, "token is required")
		}

		userID, err := security.GetUserID(token, i.secretKey)
		if err != nil {
			return status.Error(codes.Unauthenticated, "invalid token")
		}

		newCtx := context.WithValue(ss.Context(), UserIDContext, userID)

		ss = &serverStreamWithContext{
			ServerStream: ss,
			ctx:          newCtx,
		}
	}

	return handler(srv, ss)
}

// requiresAuth checks whether authentication is required for the method
func (i *AuthInterceptor) requiresAuth(method string) bool {
	return method != "/auth.Auth/Login" && method != "/auth.Auth/Register"
}

// extractToken extracts the JWT token from the incoming metadata
func (i *AuthInterceptor) extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("metadata is not provided")
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return "", errors.New("authorization header is not provided")
	}

	token := strings.TrimPrefix(authHeader[0], "Bearer ")
	if token == "" {
		return "", errors.New("token is not provided")
	}

	return token, nil
}

// serverStreamWithContext wraps the ServerStream to allow modifying its context
type serverStreamWithContext struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the modified context for the stream
func (s *serverStreamWithContext) Context() context.Context {
	return s.ctx
}
