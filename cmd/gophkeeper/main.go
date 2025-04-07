package main

import (
	"context"
	"database/sql"
	"os/signal"
	"syscall"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/application"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/config"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/persistence/db/pg"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/persistence/objstorage/minio"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/interfaces/grpc"
)

func main() {
	conf, err := config.Parse()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse config")
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	defer stop()

	logLvl, err := zerolog.ParseLevel(conf.LogLvl)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse log level")
	}
	zerolog.SetGlobalLevel(logLvl)

	db, err := sql.Open("pgx", conf.DatabaseURI)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create DB connection")
	}

	dbStorage, err := pg.New(ctx, db, conf.DatabaseMigrationsPath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize DB")
	}

	objStorage, err := minio.New(
		conf.MinIOEndpoint,
		conf.MinIOAccessKeyID,
		conf.MinIOSecretAccessKey,
		conf.MinIOBucket)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize Object Storage")
	}

	secretService := application.NewSecretService(dbStorage, objStorage, []byte(conf.RootKey))
	authService := application.NewAuthService(dbStorage, conf.JWTTokenBuildKey, conf.JWTTokenLifetime)
	srv := grpc.NewServer(secretService, authService, conf.GRPCRunAddr, conf.JWTTokenBuildKey)

	err = srv.Run(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Server encountered an error")
	}
}
