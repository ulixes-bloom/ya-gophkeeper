package grpc

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	pb "github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/interfaces/grpc/interceptors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// grpcServer defines the structure of the gRPC server, containing services and configurations
type grpcServer struct {
	secretService    domain.SecretService
	authService      domain.AuthService
	runAddr          string
	jwtTokenBuildKey string
}

// NewServer initializes and returns a new grpcServer instance with the provided services and configurations
func NewServer(secretService domain.SecretService, authService domain.AuthService, runAddr, jwtTokenBuildKey string) *grpcServer {
	newServer := grpcServer{
		secretService:    secretService,
		authService:      authService,
		runAddr:          runAddr,
		jwtTokenBuildKey: jwtTokenBuildKey,
	}
	return &newServer
}

// Run starts the gRPC server and listens for incoming requests
func (g *grpcServer) Run(ctx context.Context) error {
	errChan := make(chan error, 1)

	authInterceptor := interceptors.NewJWTInterceptor(g.jwtTokenBuildKey)

	// Chain interceptors
	interceptors := []grpc.UnaryServerInterceptor{
		authInterceptor.UnaryInterceptor,
		interceptors.WithLogging,
	}
	// Chain interceptors for streaming requests
	streamInterceptors := []grpc.StreamServerInterceptor{
		authInterceptor.StreamInterceptor,
	}

	// Create a new gRPC server with the interceptors
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(interceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	)

	// Register services
	pb.RegisterAuthServer(grpcServer, NewAuthHandler(g.authService))
	pb.RegisterSecretServiceServer(grpcServer, NewSecretHandler(g.secretService))

	// Register reflection service to enable tools like Postman to interact with the server
	reflection.Register(grpcServer)

	// Set up a TCP listener on the specified address
	listen, err := net.Listen("tcp", g.runAddr)
	if err != nil {
		log.Error().Stack().Err(err).Msgf("failed to listen on %s: %v", g.runAddr, err)
		return err
	}

	// Start the gRPC server in a goroutine to allow it to run asynchronously
	go func() {
		log.Info().Msgf("gRPC server started on %s", g.runAddr)
		errChan <- grpcServer.Serve(listen)
	}()

	select {
	case err := <-errChan:
		return fmt.Errorf("grpcapi.run: %w", err)
	case <-ctx.Done():
		log.Info().Msg("Context canceled, stopping the server...")
		grpcServer.GracefulStop()
		return nil
	}
}

// extractUserID extracts the user ID from the gRPC context.
// Returns the user ID or an error if not found.
func extractUserID(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(interceptors.UserIDContext).(string)
	if !ok {
		return "", errors.New("userID not found in context")
	}
	return userID, nil
}
