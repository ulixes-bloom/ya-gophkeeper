package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// AESEncryptingReader wraps an io.Reader and encrypts data on-the-fly.
type AESEncryptingReader struct {
	reader io.Reader     // The underlying reader
	stream cipher.Stream // The AES encryption stream
}

// AESDecryptingReader wraps an io.Reader and decrypts data on-the-fly.
type AESDecryptingReader struct {
	reader io.Reader     // The underlying reader
	stream cipher.Stream // The AES decryption stream
	closer io.Closer     // The closer if the reader supports it (e.g., io.ReadCloser)
}

// NewAESDecryptingReader creates a new AES decrypting reader with the provided key.
// The key must be 16, 24, or 32 bytes long (depending on the AES variant).
func NewAESDecryptingReader(r io.Reader, key []byte) (*AESDecryptingReader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Read the IV (Initialization Vector) from the stream
	iv := make([]byte, aes.BlockSize)
	if n, err := io.ReadFull(r, iv); err != nil {
		fmt.Println(n)
		return nil, fmt.Errorf("failed to read iv: %w", err)
	}

	stream := cipher.NewCFBDecrypter(block, iv)

	// Check if the reader supports io.Closer (e.g., io.ReadCloser)
	var closer io.Closer
	if c, ok := r.(io.Closer); ok {
		closer = c
	}

	return &AESDecryptingReader{
		reader: r,
		stream: stream,
		closer: closer,
	}, nil
}

// Read reads decrypted data from the underlying stream into the provided byte slice p.
func (a *AESDecryptingReader) Read(p []byte) (int, error) {
	n, err := a.reader.Read(p)
	if n > 0 {
		// Decrypt the data in-place using the XOR key stream method
		a.stream.XORKeyStream(p[:n], p[:n])
	}

	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("aes decrypt read error: %w", err)
	}

	return n, err
}

// Close closes the reader if it implements io.Closer.
func (a *AESDecryptingReader) Close() error {
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

// NewAESEncryptingReader creates a new AES encrypting reader with the provided key.
// The key must be 16, 24, or 32 bytes long (depending on the AES variant).
func NewAESEncryptingReader(r io.Reader, key []byte) (*AESEncryptingReader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Generate a random IV (Initialization Vector) for encryption
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to read random iv: %w", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	// Wrap the IV and data reader into a multi-reader so we can encrypt the data with the IV prepended
	ivReader := bytes.NewReader(iv)

	return &AESEncryptingReader{
		reader: io.MultiReader(ivReader, r), // Передаем IV перед данными
		stream: stream,
	}, nil
}

// Read reads encrypted data from the underlying stream and encrypts it on-the-fly.
func (a *AESEncryptingReader) Read(p []byte) (int, error) {
	n, err := a.reader.Read(p)
	if n > 0 {
		// Encrypt the data using the XOR key stream method
		a.stream.XORKeyStream(p[:n], p[:n])
	}

	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("aes decrypt read error: %w", err)
	}

	return n, nil
}

// DecryptAES decrypts the provided encrypted data using AES and the provided key.
func DecryptAES(encryptedData []byte, key []byte) ([]byte, error) {
	input := bytes.NewReader(encryptedData)
	decryptReader, err := NewAESDecryptingReader(input, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypting reader: %w", err)
	}

	var decryptedData bytes.Buffer
	if _, err := io.Copy(&decryptedData, decryptReader); err != nil {
		return nil, fmt.Errorf("failed to copy decrypted data: %w", err)
	}

	return decryptedData.Bytes(), nil
}
