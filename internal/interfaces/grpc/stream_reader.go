package grpc

import (
	"fmt"
	"io"

	pb "github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen"
)

// secretStreamReader - a custom Reader for handling gRPC stream data on the server side.
type secretStreamReader struct {
	stream pb.SecretService_CreateSecretStreamServer // gRPC stream for receiving data from the client
	buffer []byte                                    // Buffer for storing the data coming from the client
	index  int                                       // Current index in the buffer to track where to read from
}

// NewSecretStreamReader creates a grpcReader for server-side streaming (receiving data from the client)
func NewSecretStreamReader(stream pb.SecretService_CreateSecretStreamServer) io.Reader {
	return &secretStreamReader{
		stream: stream,
	}
}

// Implement the Read method for grpcReader
func (r *secretStreamReader) Read(p []byte) (int, error) {
	// If there is data already in the buffer, copy it into the provided slice 'p'
	if r.index < len(r.buffer) {
		n := copy(p, r.buffer[r.index:])
		r.index += n
		return n, nil
	}

	// Receive the next chunk of data from the gRPC stream
	if err := r.receiveNextChunk(); err != nil {
		return 0, err
	}

	// Try reading again with the newly filled buffer
	return r.Read(p)
}

// receiveNextChunk handles receiving a chunk of data from the gRPC stream and filling the buffer.
func (r *secretStreamReader) receiveNextChunk() error {
	response, err := r.stream.Recv()
	if err != nil {
		// Handle EOF (end of stream)
		if err == io.EOF {
			return io.EOF
		}
		return fmt.Errorf("grpc.receiveNextChunk: %w", err)
	}

	// Store the received data in the buffer and reset the index
	r.buffer = response.GetData()
	r.index = 0

	// If there’s no data, we return EOF explicitly, avoiding unnecessary reads
	if len(r.buffer) == 0 {
		return io.EOF
	}

	return nil
}
