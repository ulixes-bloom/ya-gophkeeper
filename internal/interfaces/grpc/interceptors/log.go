package interceptors

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

func WithLogging(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	start := time.Now()
	method := info.FullMethod

	res, err := handler(ctx, req)

	duration := time.Since(start)
	log.Debug().
		Str("method", method).
		Str("duration", duration.String()).
		Msg("got incoming grpc request")

	return res, err
}
