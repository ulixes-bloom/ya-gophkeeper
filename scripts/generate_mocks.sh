#!/bin/bash
mockgen -source=internal/domain/secret.go -destination=internal/mocks/mock_secret_service.go -package=mocks
mockgen -source=internal/domain/user.go -destination=internal/mocks/mock_auth_service.go -package=mocks

mockgen -destination=internal/mocks/mock_create_secret_stream.go -package=mocks github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen SecretService_CreateSecretStreamServer
mockgen -destination=internal/mocks/mock_get_secret_stream.go -package=mocks github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen SecretService_GetLatestSecretStreamServer