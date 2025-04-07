// Package config manages application configuration by parsing command-line arguments
// and environment variables, providing defaults, and validating settings.
package config

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/caarlos0/env"
)

// Config holds the application's configuration values.
type Config struct {
	GRPCRunAddr            string        `env:"GRPC_RUN_ADDRESS"`         // Address to run the gRPC server
	DatabaseURI            string        `env:"DATABASE_URI"`             // Database connection string
	DatabaseMigrationsPath string        `env:"DATABASE_MIGRATIONS_PATH"` // Path to database migrations
	MinIOEndpoint          string        `env:"MINIO_ENDPOINT"`           // MinIO server address
	MinIOAccessKeyID       string        `env:"MINIO_ACCESS_KEY"`         // MinIO access key
	MinIOSecretAccessKey   string        `env:"MINIO_SECRET_ACCESS_KEY"`  // MinIO secret key
	MinIOBucket            string        `env:"MINIO_BUCKET"`             // MinIO bucket name
	LogLvl                 string        `env:"LOGLVL"`                   // Log level
	RootKey                string        `env:"ROOT_KEY"`                 // Root encryption key
	JWTTokenBuildKey       string        `env:"JWT_TOKEN_BUILD_KEY"`      // JWT signing key
	JWTTokenLifetime       time.Duration `env:"JWT_TOKEN_LIFETIME"`       // JWT token expiration time
}

// Parse reads configuration values from command-line flags and validates them.
func Parse() (*Config, error) {
	conf := Config{}
	defaultConfig := GetDefault()

	flag.StringVar(&conf.GRPCRunAddr, "a", defaultConfig.GRPCRunAddr, "Address to run the gRPC server")
	flag.StringVar(&conf.DatabaseURI, "d", defaultConfig.DatabaseURI, "Database connection string")
	flag.StringVar(&conf.DatabaseMigrationsPath, "dm", defaultConfig.DatabaseMigrationsPath, "Path to database migrations")
	flag.StringVar(&conf.MinIOEndpoint, "m", defaultConfig.MinIOEndpoint, "MinIO server address")
	flag.StringVar(&conf.MinIOAccessKeyID, "ma", defaultConfig.MinIOAccessKeyID, "MinIO access key")
	flag.StringVar(&conf.MinIOSecretAccessKey, "mk", defaultConfig.MinIOSecretAccessKey, "MinIO secret key")
	flag.StringVar(&conf.MinIOBucket, "mb", defaultConfig.MinIOBucket, "MinIO bucket name")
	flag.StringVar(&conf.LogLvl, "l", defaultConfig.LogLvl, "Log level")
	flag.StringVar(&conf.RootKey, "r", defaultConfig.RootKey, "Root encryption key")
	flag.StringVar(&conf.JWTTokenBuildKey, "b", defaultConfig.JWTTokenBuildKey, "JWT signing key")
	flag.DurationVar(&conf.JWTTokenLifetime, "t", defaultConfig.JWTTokenLifetime, "JWT token expiration time")
	flag.Parse()

	if err := env.Parse(&conf); err != nil {
		return nil, fmt.Errorf("config.Parse: %w", err)
	}

	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("config.Parse: %w", err)
	}

	return &conf, nil
}

// GetDefault provides default configuration values.
func GetDefault() (conf *Config) {
	return &Config{
		GRPCRunAddr:            ":8097",
		DatabaseURI:            "host=localhost user=postgres password=26235Nn sslmode=disable",
		DatabaseMigrationsPath: "../../internal/infrastructure/persistence/db/migrations",
		MinIOEndpoint:          "127.0.0.1:9000",
		MinIOAccessKeyID:       "minioadmin",
		MinIOSecretAccessKey:   "minioadmin",
		MinIOBucket:            "ya-gophkeeper-bucket",
		LogLvl:                 "Debug",
		RootKey:                "this_is_a_correct_32_byte_key!!!",
		JWTTokenBuildKey:       "SECRET_KEY",
		JWTTokenLifetime:       8 * time.Hour,
	}
}

// Validate ensures that required configuration values are set correctly.
func (conf *Config) Validate() error {
	var errs []error

	if conf.DatabaseURI == "" {
		errs = append(errs, errors.New("DatabaseURI is required"))
	}

	if conf.JWTTokenLifetime < 0 {
		errs = append(errs, errors.New("JWT Token lifetime must not be negative"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
